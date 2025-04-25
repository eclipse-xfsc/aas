FROM --platform=$BUILDPLATFORM maven:3.8.1-openjdk-17-slim AS build

WORKDIR /app

COPY app app
COPY service service


COPY pom.xml pom.xml
COPY lombok.config lombok.config

RUN mvn clean install -DskipTests -Dcheckstyle.skip


FROM openjdk:17 as app
COPY --from=build /app/app/target/auth-app-*.jar auth-app.jar

ENTRYPOINT ["java", "-jar","/auth-app.jar"]

FROM openjdk:17 as service
COPY --from=build /app/service/target/auth-service-*.jar auth-service.jar

ENTRYPOINT ["java", "-jar","/auth-service.jar"]
