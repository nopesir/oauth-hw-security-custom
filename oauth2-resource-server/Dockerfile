FROM openjdk:8-jre-alpine

# Add my app and config
COPY target/oauth2-resource-server.jar ./

EXPOSE 9280

CMD java -jar oauth2-resource-server.jar