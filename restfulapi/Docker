# Use an OpenJDK 17 base image
FROM adoptopenjdk:17-jdk-hotspot

# Set the working directory in the container
WORKDIR /app

# Copy the necessary files to the container
COPY pom.xml .
COPY src/ ./src/

# Build the project using Maven
RUN ./mvnw clean install -DskipTests

# Expose the port that your application listens on
EXPOSE 8080

# Run the Spring Boot application
CMD ["java", "-jar", "target/restfulapi-0.0.1-SNAPSHOT.jar"]
