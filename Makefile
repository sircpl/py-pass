test:
	PYTHONPATH=. pipenv run python -m unittest discover -v
clean:
	find . -name "*.pyc" -exec rm -f {} \;
