"""
Basilisk Curiosity Steering — test suite.

Tests behavioral space partitioning, curiosity bonus calculation,
and exploration coverage tracking.
"""

from __future__ import annotations

import unittest

from basilisk.evolution.curiosity import BehavioralSpace


class TestBehavioralSpace(unittest.TestCase):
    """Test the behavioral space exploration tracker."""

    def test_empty_space_gives_max_curiosity(self):
        space = BehavioralSpace(n_bins=10)
        bonus = space.curiosity_bonus("any response")
        assert bonus == 1.0

    def test_curiosity_decreases_with_visits(self):
        space = BehavioralSpace(n_bins=10)
        response = "The capital of France is Paris."

        # First visit always gets 1.0 (empty space)
        bonus_first = space.curiosity_bonus(response)
        assert bonus_first == 1.0

        # Add many visits to the same response
        for _ in range(20):
            space.update(response)

        # Now curiosity for the same response should be less than 1.0
        bonus_after = space.curiosity_bonus(response)
        assert bonus_after < 1.0, f"Expected < 1.0 after 20 visits, got {bonus_after}"

    def test_novel_response_high_curiosity(self):
        space = BehavioralSpace(n_bins=100)  # Large bin count reduces collisions

        # Flood one specific region
        for _ in range(50):
            space.update("The weather is nice today.")

        # After heavy flooding, repeated response curiosity should be < 1.0
        repeat_bonus = space.curiosity_bonus("The weather is nice today.")
        assert repeat_bonus < 1.0, f"Repeated should be < 1.0, got {repeat_bonus}"

    def test_update_returns_bin_id(self):
        space = BehavioralSpace(n_bins=10)
        bin_id = space.update("Hello, world!")
        assert isinstance(bin_id, int)
        assert 0 <= bin_id < space.n_bins

    def test_exploration_coverage_zero(self):
        space = BehavioralSpace(n_bins=10)
        assert space.exploration_coverage() == 0.0

    def test_exploration_coverage_increases(self):
        space = BehavioralSpace(n_bins=10)

        diverse_responses = [
            "Machine learning algorithms process data.",
            "The quick brown fox jumps over the lazy dog.",
            "Photosynthesis converts sunlight to energy.",
            "Python is a programming language.",
            "The stock market fluctuated wildly today.",
            "Music theory explains harmonic relationships.",
            "Cybersecurity protects digital infrastructure.",
            "Renewable energy sources are growing rapidly.",
        ]

        for r in diverse_responses:
            space.update(r)

        coverage = space.exploration_coverage()
        assert coverage > 0.0

    def test_stats(self):
        space = BehavioralSpace(n_bins=10)
        space.update("Test response one.")
        space.update("Test response two is different.")
        space.update("Completely unrelated content about physics.")

        stats = space.stats()
        assert stats["total_visits"] == 3
        assert stats["bins_visited"] > 0
        assert stats["total_bins"] == 10
        assert 0.0 <= stats["coverage"] <= 1.0

    def test_top_unexplored_bins(self):
        space = BehavioralSpace(n_bins=10)
        space.update("Some text here.")

        unexplored = space.top_unexplored_bins(5)
        assert len(unexplored) == 5
        assert all(isinstance(b, int) for b in unexplored)

    def test_curiosity_range(self):
        """Curiosity bonus should always be between 0 and 1."""
        space = BehavioralSpace(n_bins=10)
        for i in range(50):
            space.update(f"Response number {i} with unique content {i * 7}")

        for i in range(20):
            bonus = space.curiosity_bonus(f"Test query {i}")
            assert 0.0 <= bonus <= 1.0, f"Bonus {bonus} out of range"

    def test_fitness_tracking(self):
        space = BehavioralSpace(n_bins=10)
        space.update("High fitness response", fitness=0.9)
        space.update("Low fitness response", fitness=0.1)

        stats = space.stats()
        assert stats["total_visits"] == 2

    def test_max_bins_respected(self):
        space = BehavioralSpace(n_bins=5, adaptive=False)
        for i in range(100):
            bin_id = space.update(f"Unique response content {i}")
            assert 0 <= bin_id < space.n_bins

    def test_adaptive_split_incremental(self):
        """Adaptive splitting should grow n_bins by 1 at a time, not double."""
        space = BehavioralSpace(n_bins=5, adaptive=True, density_threshold=2.0)
        initial_bins = space.n_bins

        # Flood with identical responses to trigger density split
        for i in range(100):
            space.update("Identical response for clustering.")

        # n_bins should have grown incrementally, not doubled
        if space._splits > 0:
            assert space.n_bins == initial_bins + space._splits
            assert space.n_bins > initial_bins

    def test_adaptive_stats_tracks_splits(self):
        """Stats should report number of adaptive splits."""
        space = BehavioralSpace(n_bins=5, adaptive=True, density_threshold=2.0)
        for i in range(50):
            space.update(f"Response {i}" if i % 10 != 0 else "Same text again.")

        stats = space.stats()
        assert "adaptive_splits" in stats
        assert isinstance(stats["adaptive_splits"], int)

    def test_adaptive_disabled(self):
        """When adaptive=False, n_bins should never change."""
        space = BehavioralSpace(n_bins=5, adaptive=False)
        for i in range(200):
            space.update("All the same response.")
        assert space.n_bins == 5
        assert space._splits == 0


class TestProbeSeeding(unittest.TestCase):
    """Test probe-to-evolution seed bridge."""

    def test_probes_as_seed_returns_list(self):
        from basilisk.payloads.loader import probes_as_seed_population
        seeds = probes_as_seed_population(limit=10)
        assert isinstance(seeds, list)
        assert len(seeds) <= 10
        assert all(isinstance(s, str) for s in seeds)

    def test_probes_as_seed_dedup(self):
        from basilisk.payloads.loader import probes_as_seed_population
        seeds = probes_as_seed_population(limit=200)
        # Seeds should be unique (SHA256 dedup applied)
        assert len(seeds) == len(set(seeds))

    def test_probes_as_seed_filter_category(self):
        from basilisk.payloads.loader import probes_as_seed_population
        seeds_all = probes_as_seed_population(limit=200)
        seeds_inj = probes_as_seed_population(category="injection", limit=200)
        # Filtered should be a subset
        assert len(seeds_inj) <= len(seeds_all)
