#!/bin/bash

for nb in *.ipynb; do
	echo "updating docs from ${nb}"
	md="${nb%%.ipynb}"
	jupyter nbconvert --to markdown --no-input "${nb}" && sed -i 's/^\ \ \ \ //g' "${md}.md"	
done
