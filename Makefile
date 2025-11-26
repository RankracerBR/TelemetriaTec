# Makefile for Django + PostgreSQL Docker project
DOCKER_COMPOSE ?= docker-compose

.PHONY: help build up down up-force-recreate restart logs shell web-shell db-shell test migrate makemigrations collectstatic createsuperuser clean destroy

# Default environment
ENV ?= development

install-docker-compose:
	apt install docker-compose

help:
	@echo "Django + PostgreSQL Docker Makefile"
	@echo ""
	@echo "Available commands:"
	@echo "  build           Build or rebuild services"
	@echo "  up              Create and start containers"
	@echo "  down            Stop and remove containers"
	@echo "  restart         Restart all services"
	@echo "  logs            View output from containers"
	@echo "  shell           Open shell in web container"
	@echo "  web-shell       Open shell in web container"
	@echo "  db-shell        Open PostgreSQL interactive terminal"
	@echo "  test            Run Django tests"
	@echo "  migrate         Run Django migrations"
	@echo "  makemigrations  Create new migrations"
	@echo "  collectstatic   Collect static files"
	@echo "  createsuperuser Create Django superuser"
	@echo "  clean           Remove containers, networks, and volumes"
	@echo "  destroy         Remove everything including volumes"
	@echo "  setup           Initial project setup"

# Build the services
build:
	docker-compose build

# Start services in detached mode
up:
	docker-compose up -d

# Start services with build
up-build:
	docker-compose up -d --build

# Stop and remove containers
down:
	docker-compose down

up-force-recreate:
	@echo "=> Parando e removendo container web (se existir)"
	-$(DOCKER_COMPOSE) stop web
	-$(DOCKER_COMPOSE) rm -f web
	@echo "=> Rebuild e up do serviço web"
	$(DOCKER_COMPOSE) up -d --build web

# Restart services
restart:
	docker-compose restart

# View logs
logs:
	docker-compose logs -f

# Follow logs for specific service
logs-%:
	docker-compose logs -f $*

# Open shell in web container
shell: web-shell

web-shell:
	docker-compose exec web bash

# Open PostgreSQL interactive terminal
db-shell:
	docker-compose exec db psql -U $(shell grep POSTGRES_USER .env | cut -d '=' -f2) -d $(shell grep POSTGRES_DB .env | cut -d '=' -f2)

# Run Django tests
test:
	docker-compose exec web python manage.py test --keepdb

# Run Django tests with coverage
test-coverage:
	docker-compose exec web python -m pytest --cov=.

# Run migrations
migrate:
	docker-compose exec web python manage.py migrate

# Create migrations
makemigrations:
	docker-compose exec web python manage.py makemigrations

# Create superuser
createsuperuser:
	docker-compose exec web python manage.py createsuperuser

# Run specific management command
manage:
	docker-compose exec web python manage.py $(cmd)

# Show running containers
ps:
	docker-compose ps

# Clean up containers and networks
clean:
	docker-compose down -v --remove-orphans

# Destroy everything including volumes
destroy:
	docker-compose down -v --rmi all --remove-orphans

# Backup database
backup-db:
	mkdir -p backups
	docker-compose exec db pg_dump -U $(shell grep POSTGRES_USER .env | cut -d '=' -f2) $(shell grep POSTGRES_DB .env | cut -d '=' -f2) > backups/backup_$(shell date +%Y%m%d_%H%M%S).sql

# Restore database
restore-db:
	@if [ -z "$(file)" ]; then \
		echo "Usage: make restore-db file=backup_file.sql"; \
		exit 1; \
	fi
	docker-compose exec -T db psql -U $(shell grep POSTGRES_USER .env | cut -d '=' -f2) -d $(shell grep POSTGRES_DB .env | cut -d '=' -f2) < $(file)

# Initial project setup
setup: build up-build
	@echo "Waiting for database to be ready..."
	@sleep 10
	$(MAKE) migrate
	$(MAKE) collectstatic
	@echo "Setup complete! Your Django app should be running at http://localhost:8000"

# Check service status
status:
	docker-compose ps

# View resource usage
stats:
	docker stats $$(docker ps --format={{.Names}})