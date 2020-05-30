#### Stage 1: Build the application
FROM openjdk:8-jdk-alpine as build

# Retrieve the secrets from docker-compose-build.yaml
ARG client_id
ARG client_secret

# Install envsubst on Alpine
RUN apk add gettext

# Set the current working directory inside the image
WORKDIR /app

# Copy the root pom.xml and the oauth2-authorization-server context
RUN mkdir oauth2-authorization-server 
COPY ./oauth2-authorization-server/ ./oauth2-authorization-server
COPY ./pom.xml .

# Change de directory inside the oauth2-authorization-server folder
WORKDIR /app/oauth2-authorization-server

# Substitute the ARGs of secrets passed by docker-compose-build.yaml
RUN envsubst '\$client_id \$client_secret' < src/main/resources/data.sql.template > src/main/resources/data.sql

# Show the new file
RUN cat src/main/resources/data.sql

# Enable permissions on Maven executable
RUN chmod u+x ./mvnw

# Package the application .jar
RUN ./mvnw clean package liberty:package-server -Dinclude=runnable

#### Stage 2: A minimal docker image with command to run the app 
FROM openjdk:8-jre-alpine

# Set root workdir and copy the builded .jar from the previous stage
WORKDIR /
COPY --from=build /app/oauth2-authorization-server/target/oauth2-authorization-server.jar ./

# Expose the 9080/tcp port
EXPOSE 9080

# Run the server when the docker starts
CMD ["java", "-jar", "oauth2-authorization-server.jar"]