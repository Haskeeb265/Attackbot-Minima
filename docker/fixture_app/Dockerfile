# The deliberately vulnerable fixture app. Standard library only — no pip step, so
# the image cannot drift and a run cannot fail for a reason unrelated to the engine.
FROM python:3.12-alpine

WORKDIR /app
COPY app.py /app/app.py

EXPOSE 8080
CMD ["python", "-u", "app.py"]
