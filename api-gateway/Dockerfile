FROM eclipse-temurin:17-jdk-alpine as builder
WORKDIR /app
COPY . .

# Maven Wrapper ausführbar machen
RUN chmod +x ./mvnw

RUN ./mvnw package -DskipTests

FROM eclipse-temurin:17-jre-alpine
WORKDIR /app
COPY --from=builder /app/target/api-gateway-*.jar app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
