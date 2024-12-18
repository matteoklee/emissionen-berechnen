# Stage 1: Build the application
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /app
COPY . .

# Maven Wrapper ausführbar machen
RUN chmod +x ./mvnw

RUN ./mvnw clean package -DskipTests

# Stage 2: Run the application
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=build /app/target/evidence-service-*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]
