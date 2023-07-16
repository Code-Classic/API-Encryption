FROM maven:3.8.5-openjdk-17 AS build
COPY ..
RUN mvn clean package -DskipTests

# Use a base image with OpenJDK 17 that supports Windows
FROM openjdk:17-jdk

# Copy the compiled JAR file and resource files to the container
COPY --from=build /target/restfulapi-0.0.1-SNAPSHOT.jar restfulapi.jar

# Expose the port your application listens on (assuming it's 8080)
EXPOSE 8080

# Run the Spring Boot application when the container starts
ENTRYPOINT ["java", "-jar", "restfulapi.jar"]
