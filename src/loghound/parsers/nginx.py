from pathlib import Path
from .clf import clf_can_parse, clf_parse_file


def can_parse(sample_lines: list[str]) -> bool:
    return clf_can_parse(sample_lines)


def parse_file(file_path: Path):
    return clf_parse_file(file_path, 'nginx')
