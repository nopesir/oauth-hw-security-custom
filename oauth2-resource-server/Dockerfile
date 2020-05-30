#### Stage 1: Build the application
FROM openjdk:8-jdk-alpine as build

# Set the current working directory inside the image
WORKDIR /app

# Copy the root pom.xml and the oauth2-resource-server context
RUN mkdir oauth2-resource-server 
COPY ./oauth2-resource-server/ ./oauth2-resource-server
COPY ./pom.xml .

# Change de directory inside the oauth2-resource-server folder
WORKDIR /app/oauth2-resource-server

# Enable permissions on Maven executable
RUN chmod u+x ./mvnw

# Package the application .jar
RUN ./mvnw clean package liberty:package-server -Dinclude=runnable

#### Stage 2: A minimal docker image with command to run the app 
FROM openjdk:8-jre-alpine

# Set root workdir and copy the builded .jar from the previous stage
WORKDIR /
COPY --from=build /app/oauth2-resource-server/target/oauth2-resource-server.jar ./

# Expose the 9280/tcp port
EXPOSE 9280

# Run the server when the docker starts
CMD ["java", "-jar", "oauth2-resource-server.jar"]