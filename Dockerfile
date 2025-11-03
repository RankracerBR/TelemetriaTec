FROM python:3.12.3

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
   PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
   libpq-dev gcc --no-install-recommends && \
   apt-get clean && rm -rf /var/lib/apt/lists/*

# Upgrade pip and install dependencies
COPY backend/requirements.txt /app/
RUN pip install --upgrade pip && pip install --no-cache-dir -r requirements.txt

# Copy project files into the container
COPY . /app/

# Expose the port Django will run on
EXPOSE 8000

# Run the Django development server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]