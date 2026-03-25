/*
 * Basilisk Token Analyzer — C implementation for performance-critical
 * token-level operations.
 *
 * Provides:
 *   - Fast BPE-approximate token counting
 *   - Unicode normalization for confusable detection
 *   - Entropy calculation for randomness detection
 *   - Levenshtein distance for payload similarity
 *
 * Build: gcc -shared -fPIC -O3 -o libbasilisk_tokens.so tokens.c -lm
 */

#include <ctype.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/* ============================================================
 * Approximate BPE Token Counter
 *
 * Estimates token count without requiring the full tokenizer.
 * Uses heuristics based on GPT-family tokenization patterns.
 * Accuracy: ~90% for English text, ~80% for mixed content.
 * ============================================================ */

int basilisk_estimate_tokens(const char *text) {
    if (!text || !*text) return 0;

    int tokens = 0;
    int in_word = 0;
    int consecutive_special = 0;
    int len = strlen(text);

    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)text[i];

        // Multi-byte UTF-8 sequences (CJK, emoji, etc.)
        if (c >= 0xC0) {
            int bytes;
            if (c < 0xE0)      bytes = 2;  // 2-byte
            else if (c < 0xF0) bytes = 3;  // 3-byte (CJK usually 1 token per char)
            else               bytes = 4;  // 4-byte (emoji ~2 tokens)

            if (bytes == 3) tokens += 1;    // CJK: ~1 token per char
            else if (bytes == 4) tokens += 2; // Emoji: ~2 tokens
            else tokens += 1;

            i += bytes - 1;
            in_word = 0;
            continue;
        }

        if (isalpha(c)) {
            if (!in_word) {
                tokens++;  // New word start
                in_word = 1;
            }
            consecutive_special = 0;
        } else if (isdigit(c)) {
            if (!in_word || i == 0 || !isdigit((unsigned char)text[i-1])) {
                tokens++;  // Numbers tokenize differently
            }
            in_word = 1;
            consecutive_special = 0;
        } else if (isspace(c)) {
            in_word = 0;
            consecutive_special = 0;
        } else {
            // Special characters: each is typically its own token
            tokens++;
            in_word = 0;
            consecutive_special++;
            // Repeated special chars sometimes merge
            if (consecutive_special > 2) {
                tokens--;  // Adjust for merged sequences
            }
        }
    }

    // BPE subword adjustment: long words get split
    // Average English word ~4 chars, BPE merges common subwords
    // Rough correction: add 30% for subword splits on long text
    if (tokens > 10) {
        tokens = (int)(tokens * 1.15);
    }

    return tokens > 0 ? tokens : 1;
}

/* ============================================================
 * Shannon Entropy Calculator
 *
 * Calculates the information entropy of text content.
 * Useful for detecting:
 *   - Encoded payloads (high entropy)
 *   - Repetitive filler (low entropy)
 *   - Random/obfuscated content
 * ============================================================ */

double basilisk_entropy(const char *text) {
    if (!text || !*text) return 0.0;

    int freq[256] = {0};
    int total = 0;

    for (const char *p = text; *p; p++) {
        freq[(unsigned char)*p]++;
        total++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / total;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

/* ============================================================
 * Levenshtein Edit Distance
 *
 * Standard dynamic programming implementation with space
 * optimization (O(min(m,n)) space). Used for payload similarity
 * comparison in the evolution engine's diversity tracking.
 * ============================================================ */

int basilisk_levenshtein(const char *s1, const char *s2) {
    int len1 = strlen(s1);
    int len2 = strlen(s2);

    // Ensure s1 is the shorter string for space optimization
    if (len1 > len2) {
        const char *tmp = s1; s1 = s2; s2 = tmp;
        int t = len1; len1 = len2; len2 = t;
    }

    int *prev = (int *)calloc(len1 + 1, sizeof(int));
    int *curr = (int *)calloc(len1 + 1, sizeof(int));

    if (!prev || !curr) {
        free(prev);
        free(curr);
        return -1;
    }

    for (int i = 0; i <= len1; i++) prev[i] = i;

    for (int j = 1; j <= len2; j++) {
        curr[0] = j;
        for (int i = 1; i <= len1; i++) {
            int cost = (s1[i-1] == s2[j-1]) ? 0 : 1;
            int del = prev[i] + 1;
            int ins = curr[i-1] + 1;
            int sub = prev[i-1] + cost;

            curr[i] = del < ins ? del : ins;
            if (sub < curr[i]) curr[i] = sub;
        }
        int *tmp = prev; prev = curr; curr = tmp;
    }

    int result = prev[len1];
    free(prev);
    free(curr);
    return result;
}

/* ============================================================
 * Normalized Similarity Score
 *
 * Returns 0.0 (completely different) to 1.0 (identical).
 * Based on Levenshtein distance.
 * ============================================================ */

double basilisk_similarity(const char *s1, const char *s2) {
    int maxLen = strlen(s1);
    int len2 = strlen(s2);
    if (len2 > maxLen) maxLen = len2;
    if (maxLen == 0) return 1.0;

    int dist = basilisk_levenshtein(s1, s2);
    if (dist < 0) return 0.0;

    return 1.0 - (double)dist / maxLen;
}

/* ============================================================
 * Unicode Confusable Detector
 *
 * Checks if a string contains known Unicode confusable characters
 * (homoglyphs). Returns the count of confusable characters found.
 * ============================================================ */

typedef struct {
    uint32_t codepoint;
    char ascii_equiv;
} confusable_entry;

static const confusable_entry CONFUSABLES[] = {
    // Cyrillic confusables
    {0x0430, 'a'}, {0x0435, 'e'}, {0x0456, 'i'}, {0x043E, 'o'},
    {0x0440, 'p'}, {0x0441, 'c'}, {0x0443, 'y'}, {0x0445, 'x'},
    {0x0455, 's'}, {0x04A1, 'd'}, {0x04BB, 'h'}, {0x04CF, 'l'},
    {0x044C, 'b'}, {0x043A, 'k'}, {0x043C, 'm'}, {0x0433, 'r'},
    // Greek confusables
    {0x03B1, 'a'}, {0x03B5, 'e'}, {0x03B9, 'i'}, {0x03BF, 'o'},
    {0x03C5, 'u'}, {0x03C1, 'p'}, {0x03C4, 't'}, {0x03BA, 'k'},
    {0x03C7, 'x'}, {0x03B3, 'y'},
    // Latin extended confusables
    {0x0251, 'a'}, {0x0261, 'g'}, {0x0131, 'i'},
    {0, 0} // sentinel
};

int basilisk_count_confusables(const char *text) {
    if (!text) return 0;

    int count = 0;
    const unsigned char *p = (const unsigned char *)text;

    while (*p) {
        uint32_t cp = 0;
        int bytes = 0;

        if (*p < 0x80) {
            p++;
            continue;
        } else if (*p < 0xE0) {
            cp = *p & 0x1F;
            bytes = 2;
        } else if (*p < 0xF0) {
            cp = *p & 0x0F;
            bytes = 3;
        } else {
            cp = *p & 0x07;
            bytes = 4;
        }

        for (int i = 1; i < bytes && p[i]; i++) {
            cp = (cp << 6) | (p[i] & 0x3F);
        }

        // Check against confusables table
        for (int i = 0; CONFUSABLES[i].codepoint; i++) {
            if (CONFUSABLES[i].codepoint == cp) {
                count++;
                break;
            }
        }

        p += bytes;
    }

    return count;
}

/* ============================================================
 * Batch Similarity Matrix
 *
 * Computes pairwise similarity for a set of strings.
 * Used by the evolution engine for diversity tracking.
 * Returns flattened upper-triangular matrix.
 * ============================================================ */

double *basilisk_similarity_matrix(const char **strings, int count) {
    int size = count * (count - 1) / 2;
    double *matrix = (double *)malloc(size * sizeof(double));
    if (!matrix) return NULL;

    int idx = 0;
    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            matrix[idx++] = basilisk_similarity(strings[i], strings[j]);
        }
    }

    return matrix;
}

void basilisk_free_matrix(double *matrix) {
    free(matrix);
}

/* ============================================================
 * Fast Substring Search (Boyer-Moore-Horspool)
 *
 * Returns the position of the first occurrence, or -1.
 * Faster than strstr() for longer patterns.
 * ============================================================ */

int basilisk_fast_search(const char *text, const char *pattern) {
    int tlen = strlen(text);
    int plen = strlen(pattern);

    if (plen == 0) return 0;
    if (plen > tlen) return -1;

    // Build skip table
    int skip[256];
    for (int i = 0; i < 256; i++) skip[i] = plen;
    for (int i = 0; i < plen - 1; i++) {
        skip[(unsigned char)pattern[i]] = plen - 1 - i;
    }

    // Search
    int i = plen - 1;
    while (i < tlen) {
        int j = plen - 1;
        int k = i;
        while (j >= 0 && tolower(text[k]) == tolower(pattern[j])) {
            j--;
            k--;
        }
        if (j < 0) return k + 1;
        i += skip[(unsigned char)tolower(text[i])];
    }

    return -1;
}

/* ============================================================
 * Multi-Pattern Counter
 *
 * Counts occurrences of multiple patterns in text.
 * Returns array of counts, one per pattern.
 * ============================================================ */

int *basilisk_multi_count(const char *text, const char **patterns, int num_patterns) {
    int *counts = (int *)calloc(num_patterns, sizeof(int));
    if (!counts) return NULL;

    for (int p = 0; p < num_patterns; p++) {
        int plen = strlen(patterns[p]);
        if (plen == 0) continue;

        const char *pos = text;
        while ((pos = strstr(pos, patterns[p])) != NULL) {
            counts[p]++;
            pos += plen;
        }
    }

    return counts;
}

void basilisk_free_counts(int *counts) {
    free(counts);
}
