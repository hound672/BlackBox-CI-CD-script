.PHONY: tox
tox: requirements.txt requirements-dev.txt
	tox

poetry.lock: pyproject.toml
	poetry lock --no-update

requirements.txt: poetry.lock
	poetry export --without-hashes -o "$@"

requirements-dev.txt: poetry.lock
	poetry export --without-hashes --dev -o "$@"

.PHONY: fmt
fmt:
	brunette --quiet .
	isort --quiet --profile=black .

.PHONY: lint
lint:
	brunette --check .
	isort --check .
	flake8 .
	mypy --strict --no-error-summary .
