# Use a base image with OpenJDK 17
FROM openjdk:17-jdk

# Set the working directory in the container
WORKDIR /target

# Copy the compiled JAR file to the container
COPY target/restfulapi-0.0.1-SNAPSHOT.jar

# Expose the port your application listens on (assuming it's 8080)
EXPOSE 8080

# Run the Spring Boot application when the container starts
CMD ["java", "-jar", "/target/restfulapi-0.0.1-SNAPSHOT.jar"]
