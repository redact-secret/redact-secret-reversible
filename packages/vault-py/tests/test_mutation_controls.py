"""The mutation table (``mutation_controls.py``) is maintained: every mutant still applies exactly once and still
produces valid Python. This does not run the mutants; ``python tests/mutation_controls.py`` does, and its results are in
``docs/research/qualification-python-persistence-0.1.0b3.md``."""

from __future__ import annotations

import ast
import sys

import pytest
from mutation_controls import MUTANTS, PACKAGE

pytestmark = pytest.mark.skipif(sys.version_info < (3, 11), reason="the persistent modules need Python 3.11")


def test_the_mutant_ids_are_unique_and_every_mutant_names_a_test_or_a_schedule() -> None:
    ids = [mutant.id for mutant in MUTANTS]
    assert len(ids) == len(set(ids))
    assert all(mutant.pytest_args or mutant.schedules for mutant in MUTANTS)
    assert len(MUTANTS) >= 30


@pytest.mark.parametrize("mutant", MUTANTS, ids=[m.id for m in MUTANTS])
def test_every_mutant_applies_exactly_once_and_stays_valid_python(mutant) -> None:  # type: ignore[no-untyped-def]
    text = (PACKAGE / mutant.file).read_text(encoding="utf-8")
    assert text.count(mutant.old) == 1, f"{mutant.id}: the text to change occurs {text.count(mutant.old)} times"
    assert mutant.old != mutant.new
    ast.parse(text.replace(mutant.old, mutant.new))
