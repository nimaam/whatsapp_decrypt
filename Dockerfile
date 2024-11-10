# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set the working directory in the container to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 8080 for the Flask app
EXPOSE 8080

# Define environment variable
ENV FLASK_APP=decrypt_media.py

# Run the application
#CMD ["python", "decrypt_media.py"]
