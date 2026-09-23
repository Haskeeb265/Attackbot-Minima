# The OOB collaborator. Standard library only, same reasoning as the fixture app:
# the component that produces the strongest evidence class in the engine should be
# the one with the least that can go wrong.
FROM python:3.12-alpine

WORKDIR /app
COPY app.py /app/app.py

ENV OOB_PORT=9009 \
    OOB_LOG=/data/interactions.jsonl

EXPOSE 9009
CMD ["python", "-u", "app.py"]
