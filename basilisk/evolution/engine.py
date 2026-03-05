"""
Basilisk Evolution Engine — Smart Prompt Evolution for Natural Language (SPE-NL).

The core genetic algorithm that evolves prompt payloads based on model feedback.
Ported from WSHawk's Smart Payload Evolution concept, adapted for NL attacks.

This is the killer differentiator — no other AI red team tool has this.
"""

from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass, field
from typing import Any, Callable

from basilisk.core.config import EvolutionConfig
from basilisk.evolution.crossover import crossover
from basilisk.evolution.fitness import AttackGoal, FitnessResult, evaluate_fitness
from basilisk.evolution.operators import ALL_OPERATORS, MutationOperator, get_random_operator
from basilisk.evolution.population import Individual, Population
from basilisk.providers.base import ProviderAdapter, ProviderMessage

logger = logging.getLogger("basilisk.evolution")


@dataclass
class EvolutionResult:
    """Complete result of an evolution run."""
    best_individual: Individual | None = None
    breakthroughs: list[Individual] = field(default_factory=list)
    total_generations: int = 0
    total_mutations: int = 0
    total_evaluations: int = 0
    generation_stats: list[dict[str, Any]] = field(default_factory=list)
    stagnated: bool = False

    @property
    def success(self) -> bool:
        return len(self.breakthroughs) > 0


class EvolutionEngine:
    """
    Smart Prompt Evolution for Natural Language (SPE-NL).

    Genetic algorithm that evolves prompt payloads by:
    1. Seeding population from payload database
    2. Evaluating each payload's fitness against the target
    3. Selecting top performers via tournament selection
    4. Applying mutation operators (synonym swap, encoding, role injection, etc.)
    5. Crossing over successful payloads to breed hybrids
    6. Repeating for N generations or until breakthrough
    """

    def __init__(
        self,
        provider: ProviderAdapter,
        config: EvolutionConfig | None = None,
        on_generation: Callable[..., Any] | None = None,
        on_breakthrough: Callable[..., Any] | None = None,
        attacker_provider: ProviderAdapter | None = None,
    ) -> None:
        self.provider = provider
        self.config = config or EvolutionConfig()
        self.attacker_provider = attacker_provider
        self.population = Population(
            max_size=self.config.population_size,
            elite_count=self.config.elite_count,
        )
        self.on_generation = on_generation
        self.on_breakthrough = on_breakthrough
        self.operators: list[MutationOperator] = [op() for op in ALL_OPERATORS]
        
        # Initialize LLM operator if provider available
        from basilisk.evolution.operators import LLMMutation
        self.llm_operator = None
        if self.attacker_provider:
            self.llm_operator = LLMMutation(
                provider=self.attacker_provider,
                model=self.config.attacker_model
            )
            
        self._seen_responses: set[str] = set()
        self._total_mutations = 0
        self._total_evaluations = 0
        self._best_fitness_ever = 0.0  # For relative breakthroughs

    async def evolve(
        self,
        seed_payloads: list[str],
        goal: AttackGoal,
        system_context: list[ProviderMessage] | None = None,
    ) -> EvolutionResult:
        """
        Run the full evolution loop.

        Args:
            seed_payloads: Initial payload population
            goal: What constitutes a successful attack
            system_context: Optional system/context messages to prepend

        Returns:
            EvolutionResult with breakthroughs and statistics
        """
        result = EvolutionResult()
        context = system_context or []

        # Seed population
        selected = random.sample(seed_payloads, min(self.config.population_size, len(seed_payloads)))
        self.population.seed(selected)

        logger.info(
            f"Evolution started: pop={len(self.population.individuals)}, "
            f"gens={self.config.generations}, goal={goal.description}"
        )

        stagnation_counter = 0
        prev_best_fitness = 0.0
        # Warm-up: don't allow stagnation exit during the first 30% of generations (min 3)
        warmup_gens = max(3, self.config.generations * 3 // 10)

        for gen in range(self.config.generations):
            # Evaluate current population
            await self._evaluate_population(goal, context)

            # Check for breakthroughs (Relative Breakthrough Logic)
            # A breakthrough is any individual that:
            # 1. Has fitness > 0.7 (high quality)
            # 2. IS BETTER than anything we have seen before
            # 3. OR meets the absolute fitness_threshold
            for ind in self.population.individuals:
                is_high_quality = ind.fitness >= 0.7
                is_threshold_met = ind.fitness >= self.config.fitness_threshold

                if is_high_quality or is_threshold_met:
                    if ind.payload not in [b.payload for b in result.breakthroughs]:
                        self._best_fitness_ever = max(self._best_fitness_ever, ind.fitness)
                        result.breakthroughs.append(ind)
                        logger.info(f"Breakthrough Found! Fitness: {ind.fitness:.3f}")
                        if self.on_breakthrough:
                            cb = self.on_breakthrough(ind, gen)
                            if hasattr(cb, "__await__"):
                                await cb

            # Generation stats
            stats = {
                "generation": gen + 1,
                "total_generations": self.config.generations,
                "best_fitness": self.population.best.fitness if self.population.best else 0.0,
                "avg_fitness": self.population.avg_fitness,
                "population_size": len(self.population.individuals),
                "mutations_applied": 0,
                "breakthroughs": len(result.breakthroughs),
                "diversity": self.population.diversity_score,
                "best_payload": self.population.best.payload if self.population.best else "",
            }

            # Stagnation detection — only after warm-up period
            current_best = self.population.best.fitness if self.population.best else 0.0
            current_diversity = self.population.diversity_score
            if gen >= warmup_gens:
                # Both fitness AND diversity must be stagnant to trigger exit.
                # If diversity is still high (>0.3), the population is still exploring.
                fitness_stagnant = abs(current_best - prev_best_fitness) < 0.05
                diversity_low = current_diversity < 0.3
                if fitness_stagnant and diversity_low:
                    stagnation_counter += 1
                elif not fitness_stagnant:
                    stagnation_counter = 0

                if stagnation_counter >= self.config.stagnation_limit:
                    logger.info(f"Stagnation detected at gen {gen + 1} (diversity={current_diversity:.2f}), stopping evolution")
                    result.stagnated = True
                    stats["stagnated"] = True
                    result.generation_stats.append(stats)
                    if self.on_generation:
                        cb = self.on_generation(stats)
                        if hasattr(cb, "__await__"):
                            await cb
                    break
            prev_best_fitness = current_best

            # Early exit if we found breakthrough — but not before warmup
            if gen >= warmup_gens and current_best >= self.config.fitness_threshold:
                logger.info(f"Fitness threshold reached at gen {gen + 1}")
                result.generation_stats.append(stats)
                if self.on_generation:
                    cb = self.on_generation(stats)
                    if hasattr(cb, "__await__"):
                        await cb
                break

            # Produce next generation
            offspring = await self._produce_offspring(goal)
            stats["mutations_applied"] = len(offspring)
            self._total_mutations += len(offspring)

            gen_stats = self.population.advance_generation(offspring)
            result.generation_stats.append(stats)

            if self.on_generation:
                cb = self.on_generation(stats)
                if hasattr(cb, "__await__"):
                    await cb

            logger.info(
                f"Gen {gen + 1}: best={current_best:.3f}, "
                f"avg={self.population.avg_fitness:.3f}, "
                f"breakthroughs={len(result.breakthroughs)}"
            )

        result.best_individual = self.population.best
        result.total_generations = self.population.generation
        result.total_mutations = self._total_mutations
        result.total_evaluations = self._total_evaluations
        return result

    async def _evaluate_population(
        self,
        goal: AttackGoal,
        context: list[ProviderMessage],
    ) -> None:
        """Evaluate fitness of all individuals in the population."""
        conc = getattr(self.config, "max_concurrent", 5)
        semaphore = asyncio.Semaphore(conc)

        async def eval_one(ind: Individual) -> None:
            async with semaphore:
                try:
                    messages = list(context) + [
                        ProviderMessage(role="user", content=ind.payload)
                    ]
                    resp = await self.provider.send(
                        messages,
                        temperature=self.config.temperature,
                        max_tokens=2048,
                    )
                    ind.response = resp.content
                    self._seen_responses.add(resp.content[:200])

                    fitness_result = evaluate_fitness(
                        resp.content, goal, self._seen_responses
                    )
                    ind.fitness = fitness_result.total_score
                    self._total_evaluations += 1
                except Exception as e:
                    logger.error(f"Evaluation failed: {e}")
                    ind.fitness = 0.0

        tasks = [eval_one(ind) for ind in self.population.individuals]
        await asyncio.gather(*tasks)

    async def _produce_offspring(self, goal: AttackGoal) -> list[Individual]:
        """Produce new offspring via mutation and crossover."""
        offspring: list[Individual] = []
        target_count = self.config.population_size - self.config.elite_count

        tasks = []
        
        async def create_one():
            if random.random() < self.config.crossover_rate and len(self.population.individuals) >= 2:
                # Crossover (synchronous)
                parent_a = self.population.tournament_select(self.config.tournament_size)
                parent_b = self.population.tournament_select(self.config.tournament_size)
                cx_result = crossover(parent_a.payload, parent_b.payload)
                return Individual(
                    payload=cx_result.offspring,
                    parent_id=parent_a.id,
                    operator_used=f"crossover:{cx_result.strategy}",
                )
            else:
                # Mutation
                parent = self.population.tournament_select(self.config.tournament_size)
                
                # If LLM mutator available, use it with a high probability (70%)
                if self.llm_operator and random.random() < 0.7:
                    logger.info(f"Gen {self.population.generation}: Gemini is mutating a payload...")
                    mut_result = await self.llm_operator.async_mutate(parent.payload, goal.description)
                    if "failed" in mut_result.description:
                        logger.error(f"Gemini Mutation Failed: {mut_result.description}")
                        # Fallback to standard operator instead of wasting a population slot
                        operator = random.choice(self.operators)
                        mut_result = operator.mutate(parent.payload)
                else:
                    operator = random.choice(self.operators)
                    mut_result = operator.mutate(parent.payload)
                    
                return Individual(
                    payload=mut_result.mutated,
                    parent_id=parent.id,
                    operator_used=mut_result.operator_name,
                )

        # Build offspring in parallel (limited for LLM calls)
        sem = asyncio.Semaphore(15)
        
        async def sem_create():
            async with sem:
                return await create_one()

        tasks = [sem_create() for _ in range(target_count)]
        offspring = await asyncio.gather(*tasks)
        return list(offspring)
