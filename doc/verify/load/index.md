## Load Test Results

Load tests were implemented in JMeter tool. Test scenarios are stored in project repository, see `/tests` folder.

Tests were applied on service deployed in public test environment, accessible at [http://78.138.66.89:9000](http://78.138.66.89:9000/actuator/info). Only one service instance was tested. The tests objective was to get the dependence of throughput and latency vs the number of concurrent users. Tests were run in a single JMeter instance.


**SSI Backchannel Login test**

test steps (requests) follow [SSI Backchannel Login scenario](../../functions/ssi_login)

![SSI Login Charts](./images/login-load-charts.png "SSI Login Charts")

The errors we see with 500+ concurrent users happened on the client (test) side. To test higher number of users we have to run several instances of JMeter.

[Excel file with test details](./load_tests_login.xlsx)
  

**SSI IAT Provision test**

test steps follow [SSI IAT Provision scenario](../../functions/iat_provider)

[Excel file with test details](./graphs_IAT_tests.xlsx)