Для сборки и запуска:

Только приложение:

```bash
docker build -t fastapi-app .
docker run -p 8000:8000 fastapi-app
```

С помощью docker-compose:

```bash
docker-compose up --build
```