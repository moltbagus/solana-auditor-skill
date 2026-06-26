"""Property-based tests for Solana Auditor Shiba Skill.

These tests use Hypothesis to check general properties of the skill's core
algorithms — things that should be true for ALL valid inputs, not just
specific examples.

Run with: pytest tests/fuzz/ --hypothesis-show-statistics
  or:     python -m pytest tests/fuzz/ -x -v
"""
