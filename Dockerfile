FROM eclipse-temurin:17-jdk
LABEL authors="Qamar Islam"
WORKDIR /app
COPY target/*.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]