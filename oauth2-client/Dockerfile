#### Stage 1: Build the application
FROM openjdk:8-jdk-alpine as build

# Retrieve the secrets from docker-compose-build.yaml
ARG client_id
ARG client_secret

# Install envsubst on Alpine
RUN apk add gettext

# Set the current working directory inside the image
WORKDIR /app

# Copy the root pom.xml and the oauth2-client context
RUN mkdir oauth2-client 
COPY ./oauth2-client/ ./oauth2-client
COPY ./pom.xml .

# Change de directory inside the oauth2-client folder
WORKDIR /app/oauth2-client

# Enable permissions on Maven executable
RUN chmod u+x ./mvnw

# Substitute the ARGs of secrets passed by docker-compose-build.yaml
RUN envsubst '\$client_id \$client_secret' < src/main/resources/META-INF/microprofile-config.properties.template > src/main/resources/META-INF/microprofile-config.properties

# Show the new file
RUN cat src/main/resources/META-INF/microprofile-config.properties

# Package the application .jar
RUN ./mvnw clean package liberty:package-server -Dinclude=runnable

#### Stage 2: A minimal docker image with command to run the app 
FROM openjdk:8-jre-alpine

# Set root workdir and copy the builded .jar from the previous stage
WORKDIR /
COPY --from=build /app/oauth2-client/target/oauth2-client.jar ./

# Expose the 9180/tcp port
EXPOSE 9180

# Run the server when the docker starts
CMD ["java", "-jar", "oauth2-client.jar"]