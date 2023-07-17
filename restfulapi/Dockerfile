# Use a base image with OpenJDK 17 that supports Windows
FROM openjdk:17-jdk

# Set the working directory in the container
WORKDIR /app

# Expose the port your application listens on (assuming it's 8080)
EXPOSE 8080

# Run the Spring Boot application when the container starts
CMD ["java", "-jar", "/app/restfulapi.jar"]
