FROM openjdk:8-jre-alpine

# Add my app and config
COPY target/oauth2-client.jar ./

EXPOSE 9180

CMD java -jar oauth2-client.jar