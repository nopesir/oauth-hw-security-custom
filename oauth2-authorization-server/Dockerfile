FROM openjdk:8-jre-alpine

# Add my app and config
COPY target/oauth2-authorization-server.jar ./

EXPOSE 9080

CMD java -jar oauth2-authorization-server.jar