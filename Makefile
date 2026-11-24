.PHONY: help install install-full test lint cov clean build

help:
	@echo "make install       - install the package (core)"
	@echo "make install-full  - install with all extras (docs, archives, remote, ocr, rules)"
	@echo "make test          - run the test suite"
	@echo "make cov           - tests with coverage report"
	@echo "make lint          - ruff"
	@echo "make build         - build wheel/sdist"
	@echo "make clean         - remove build artifacts"

install:
	pip install -e .

install-full:
	pip install -e ".[full,dev]"

test:
	python -m pytest

cov:
	python -m pytest --cov=exhume --cov-report=term-missing

lint:
	ruff check exhume tests

build:
	python -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache .coverage htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
