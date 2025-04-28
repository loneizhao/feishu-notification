# Dockerfile for feishu-notification

# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
# Using --no-cache-dir reduces image size
RUN pip install --no-cache-dir -r requirements.txt

# Copy your application code into the container
COPY . .

# --- IMPORTANT ---
# Adjust the CMD and EXPOSE lines based on your application:
# If main.py runs a web server (e.g., Flask, FastAPI):
# ENV PORT 8080 # Or the port your app listens on
# EXPOSE ${PORT}
# CMD ["python", "main.py"] # Or e.g., ["gunicorn", "-b", ":${PORT}", "main:app"]

# If main.py is a script that runs and exits:
CMD ["python", "main.py"]

