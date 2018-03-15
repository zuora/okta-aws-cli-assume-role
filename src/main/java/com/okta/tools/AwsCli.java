/*!
 * Copyright (c) 2016, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

package com.okta.tools;

import static com.okta.tools.AwsCli.OktaFactor.google;
import static com.okta.tools.AwsCli.OktaFactor.none;
import static com.okta.tools.AwsCli.OktaFactor.okta_verify;
import static com.okta.tools.AwsCli.OktaFactor.question;
import static com.okta.tools.AwsCli.OktaFactor.sms;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;

import com.amazonaws.AmazonClientException;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.profile.ProfilesConfigFile;
import com.amazonaws.auth.profile.internal.BasicProfile;
import com.amazonaws.auth.profile.internal.ProfileKeyConstants;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClient;
import com.amazonaws.services.identitymanagement.model.AttachedPolicy;
import com.amazonaws.services.identitymanagement.model.GetPolicyRequest;
import com.amazonaws.services.identitymanagement.model.GetPolicyResult;
import com.amazonaws.services.identitymanagement.model.GetPolicyVersionRequest;
import com.amazonaws.services.identitymanagement.model.GetPolicyVersionResult;
import com.amazonaws.services.identitymanagement.model.GetRolePolicyRequest;
import com.amazonaws.services.identitymanagement.model.GetRolePolicyResult;
import com.amazonaws.services.identitymanagement.model.GetRoleRequest;
import com.amazonaws.services.identitymanagement.model.GetRoleResult;
import com.amazonaws.services.identitymanagement.model.ListAttachedRolePoliciesRequest;
import com.amazonaws.services.identitymanagement.model.ListAttachedRolePoliciesResult;
import com.amazonaws.services.identitymanagement.model.ListRolePoliciesRequest;
import com.amazonaws.services.identitymanagement.model.ListRolePoliciesResult;
import com.amazonaws.services.identitymanagement.model.Policy;
import com.amazonaws.services.identitymanagement.model.Role;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClient;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLRequest;
import com.amazonaws.services.securitytoken.model.AssumeRoleWithSAMLResult;
import com.amazonaws.util.StringUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.InputMismatchException;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;
import java.util.Set;

public class AwsCli {

    static enum OktaFactor {
        none, question, sms, google, okta_verify;
    }

    private static final String SECOND_FACTOR_TOKEN_OPT = "tok";

    private static final String SECOND_FACTOR_TYPE_OPT = "typ";

    private static final String PASSWORD_OPT = "psw";

    private static final String USERNAME_OPT = "usr";

    private static final String ROLE_OPT = "r";

    private static final String PROFILE_OPT = "p";

    private static Set<String> SUPPORTED_2FA = new HashSet<String>(Arrays.asList(new String[]{"google"}));

    //User specific variables
    private static String oktaOrg = "";
    private static String oktaAWSAppURL = "";
    private static String oktaUserName = "";
    private static OktaFactor oktaAuthMethod = none;
    private static String awsIamKey = null;
    private static String awsIamSecret = null;

    private static String crossAccountRoleName = null;
    private static String roleToAssume; //the ARN of the role the user wants to eventually assume (not the cross-account role, the "real" role in the target account)
    private static int selectedPolicyRank; //the zero-based rank of the policy selected in the selected cross-account role (in case there is more than one policy tied to the current policy)
    private static final Logger logger = LogManager.getLogger(AwsCli.class);

    private static CommandLine cli;
    private static Options cliOptions;

    public static void main(String[] args) throws Exception {
        awsSetup();

        cliOptions = createCliOptions();
        if ((0 < args.length) && (args[0].equalsIgnoreCase("help") || args[0].equalsIgnoreCase("--help"))) {
            printUsage();
            System.exit(0);
        }

        if (1 < args.length) {
            CommandLineParser parser = new DefaultParser();
            cli = parser.parse(cliOptions, args);
        }

        String profileName = null;
        if (1 == args.length) {
            profileName = args[0];
        } else if ((null != cli) && cli.hasOption(PROFILE_OPT)) {
            profileName = cli.getOptionValue(PROFILE_OPT);
        }

        if (null == profileName) {
            profileName = extractCredentials();
        } else {
            extractCredentials(profileName);
        }

        // Step #1: Initiate the authentication and capture the SAML assertion.
        String resultSAML = "";
        try {
            String strOktaSessionToken = oktaAuthntication();
            if (!strOktaSessionToken.equalsIgnoreCase(""))
            // Step #2 get SAML assertion from Okta.
            {
                resultSAML = awsSamlHandler(strOktaSessionToken);
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (UnknownHostException e) {
            logger.error("\nUnable to establish a connection with AWS. \nPlease verify that your OKTA_AWS_APP_URL parameter is correct and try again");
            System.exit(0);
        } catch (ClientProtocolException e) {
            logger.error("\nNo Org found, please specify an OKTA_ORG parameter in your okta properties file");
            System.exit(0);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Step #3: Assume an AWS role using the SAML Assertion from Okta.
        AssumeRoleWithSAMLResult assumeResult = assumeAWSRole(resultSAML);
        com.amazonaws.services.securitytoken.model.AssumedRoleUser aru = assumeResult.getAssumedRoleUser();
        String arn = aru.getArn();

        // Step #4: Get the final role to assume and update the config file to add it to the user's profile.
        GetRoleToAssume(crossAccountRoleName);
        logger.trace("Role to assume ARN: " + roleToAssume);

        // Set profile name to default if it was not specified on the command line.
        if ((0 == args.length) && (null == profileName)) {
            profileName = createDefaultProfileName(arn);
        }

        // Step #5: Write the credentials to ~/.aws/credentials.
        setAWSCredentials(assumeResult, profileName);

        UpdateConfigFile(profileName, roleToAssume);

        // Print Final message
        if (null == cli) {
            resultMessage(profileName);
        }
    }

    private static void printUsage() {
        HelpFormatter formatter = new HelpFormatter();
        String preamble = "\n"
                + "The okta-aws-login supports multiple AWS accounts through configuration\n"
                + "profiles in the local okta properties file. To switch profiles use\n"
                + "the --profile (or -p) command line option followed by the name of the\n"
                + "desired profile. The profiles in the okta-aws-login properties\n"
                + "file correspond with the profiles in your AWS config file.\n\n";
        formatter.printHelp(preamble, cliOptions);
    }

    /* Authenticates users credentials via Okta, return Okta session token
     * Postcondition: returns String oktaSessionToken
     * */
    private static String oktaAuthntication() throws ClientProtocolException, JSONException, IOException {
        Scanner scanner = new Scanner(System.in, "UTF-8");
        CloseableHttpResponse responseAuthenticate = null;
        int requestStatus = 0;

        //Redo sequence if response from AWS doesn't return 200 Status
        while (requestStatus != 200) {

            String oktaUsername;
            if ((null != cli) && cli.hasOption(USERNAME_OPT)) {
                oktaUsername = cli.getOptionValue(USERNAME_OPT);
            } else if (oktaUserName != null) {
                oktaUsername = oktaUserName; // clearly quality code
                System.out.printf("Username is %s (from profile)%n", oktaUsername);
            } else {
                // Prompt for user credentials
                System.out.print("Username: ");
                oktaUsername = scanner.next();
            }

            String oktaPassword;
            if ((null != cli) && cli.hasOption(PASSWORD_OPT)) {
                oktaPassword = cli.getOptionValue(PASSWORD_OPT);
            } else {
                Console console = System.console();
                if (console != null) {
                    oktaPassword = new String(console.readPassword("Password: "));
                } else { // hack to be able to debug in an IDE
                    System.out.print("Password: ");
                    oktaPassword = scanner.next();
                }
            }

            responseAuthenticate = authnticateCredentials(oktaUsername, oktaPassword);
            requestStatus = responseAuthenticate.getStatusLine().getStatusCode();
            authnFailHandler(requestStatus, responseAuthenticate);
        }

        //Retrieve and parse the Okta response for session token
        String outputAuthenticate = responseBodyToString(responseAuthenticate);
        JSONObject jsonObjResponse = new JSONObject(outputAuthenticate);

        responseAuthenticate.close();

        if (jsonObjResponse.getString("status").equals("MFA_REQUIRED")) {
            return mfa(jsonObjResponse);
        } else {
            return jsonObjResponse.getString("sessionToken");
        }
    }

    private static String responseBodyToString(CloseableHttpResponse response) throws IOException {
        try (BufferedReader br = new BufferedReader(new InputStreamReader((response.getEntity().getContent()), UTF_8))) {
            return br.readLine();
        }
    }

    /*Uses user's credentials to obtain Okta session Token */
    private static CloseableHttpResponse authnticateCredentials(String username, String password) throws JSONException, ClientProtocolException, IOException {
        HttpPost httpost = null;
        CloseableHttpClient httpClient = HttpClients.createDefault();

        //HTTP Post request to Okta API for session token
        httpost = new HttpPost("https://" + oktaOrg + "/api/v1/authn");
        httpost.addHeader("Accept", "application/json");
        httpost.addHeader("Content-Type", "application/json");
        httpost.addHeader("Cache-Control", "no-cache");

        //construction of request JSON
        JSONObject jsonObjRequest = new JSONObject();
        jsonObjRequest.put("username", username);
        jsonObjRequest.put("password", password);

        StringEntity entity = new StringEntity(jsonObjRequest.toString(), UTF_8);
        entity.setContentType("application/json");
        httpost.setEntity(entity);

        return httpClient.execute(httpost);
    }

    /* creates required AWS credential file if necessary" */
    private static void awsSetup() throws FileNotFoundException, UnsupportedEncodingException {
        //check if credentials file has been created
        File f = new File(System.getProperty("user.home") + "/.aws/credentials");
        //creates credentials file if it doesn't exist yet
        if (!f.exists()) {
            if (!f.getParentFile().mkdirs()) {
                throw new FileNotFoundException("Could not create " + f.getParentFile().getAbsolutePath());
            }

            PrintWriter writer = new PrintWriter(f, "UTF-8");
            writer.println("[default]");
            writer.println("aws_access_key_id=");
            writer.println("aws_secret_access_key=");
            writer.close();
        }

        f = new File(System.getProperty("user.home") + "/.aws/config");
        //creates credentials file if it doesn't exist yet
        if (!f.exists()) {
            if (!f.getParentFile().mkdirs()) {
                throw new FileNotFoundException("Could not create " + f.getParentFile().getAbsolutePath());
            }

            PrintWriter writer = new PrintWriter(f, "UTF-8");
            writer.println("[profile default]");
            writer.println("output = json");
            writer.println("region = us-east-1");
            writer.close();
        }
    }

    /* Parses application's config file for app URL and Okta Org */
    private static String extractCredentials() throws IOException {
        Properties properties;
        String profileName = null;
        try {
            profileName = resolveProfileName();
            properties = getOktaPropertiesFromAwsProfile(profileName);
        } catch (IllegalArgumentException ex) {
            properties = getOktaPropertiesFromLocalConfig();
        }

        // Extract oktaOrg and oktaAWSAppURL from Okta settings file.
        oktaOrg = properties.getProperty("OKTA_ORG");
        oktaAWSAppURL = properties.getProperty("OKTA_AWS_APP_URL");
        oktaUserName = properties.getProperty("OKTA_USERNAME");
        oktaAuthMethod = OktaFactor.valueOf(properties.getProperty("OKTA_AUTH_METHOD", "none"));
        awsIamKey = properties.getProperty("AWS_IAM_KEY");
        awsIamSecret = properties.getProperty("AWS_IAM_SECRET");
        return profileName;
    }

    // shame ... shame ... shame ...
    private static final File[] FILES = new File[]{new File("config.properties"), new File(System.getProperty("USER.HOME"), ".okta-config.properties")};

    static String resolveProfileName() throws FileNotFoundException {

        for (File file : FILES) {
            if (file.exists()) {
                ProfilesConfigFile awsProfilesConfigFile = new ProfilesConfigFile(file);
                Set<String> keySet = awsProfilesConfigFile.getAllBasicProfiles().keySet();
                String keySetArray[] = keySet.toArray(new String[keySet.size()]);
                if (1 > keySetArray.length) {
                    throw new IllegalStateException("The Okta configuration file is empty.");
                } else if (1 == keySetArray.length) {
                    return keySetArray[0];
                } else {
                    System.out.println("Your '" + file.getAbsolutePath() + "' file contains multiple profiles, please select one:");
                    for (int i = 0; i < keySetArray.length; i++) {
                        System.out.println(String.format("[%d] %s", i + 1, keySetArray[i]));
                    }
                    int selection = numSelection(keySetArray.length);
                    return keySetArray[selection];
                }
            }
        }
        throw new FileNotFoundException("No config file ($HOME/.okta-config.properties and config.properties) found");
    }

    private static Properties getOktaPropertiesFromLocalConfig() throws FileNotFoundException, IOException {
        for (File file : FILES) {
            if (file.exists()) {
                try (InputStreamReader reader = new InputStreamReader(new FileInputStream(file), US_ASCII)) {
                    Properties properties = new Properties();
                    properties.load(reader);
                    return properties;
                }
            }
        }
        throw new FileNotFoundException("No config file ($HOME/.okta-config.properties and config.properties) found");
    }

    private static void extractCredentials(String profileName) throws IOException {
        Properties properties = getOktaPropertiesFromAwsProfile(profileName);

        oktaOrg = properties.getProperty("OKTA_ORG");
        oktaAWSAppURL = properties.getProperty("OKTA_AWS_APP_URL");
        oktaUserName = properties.getProperty("OKTA_USERNAME");
        oktaAuthMethod = OktaFactor.valueOf(properties.getProperty("OKTA_AUTH_METHOD", "none"));
        awsIamKey = properties.getProperty("AWS_IAM_KEY");
        awsIamSecret = properties.getProperty("AWS_IAM_SECRET");
    }

    static Properties getOktaPropertiesFromAwsProfile(String profileName) throws FileNotFoundException, IOException {
        ProfilesConfigFile awsProfilesConfigFile;
        for (File file : FILES) {
            if (file.exists()) {
                try {
                    awsProfilesConfigFile = new ProfilesConfigFile(file);
                } catch (IllegalArgumentException ex) {
                    System.err.println("The Okta configuration file '" + file.getAbsolutePath() + "' is not in multiple profile format."
                            + " Will try to load configuration in single profile mode.");
                    return getOktaPropertiesFromLocalConfig();
                }
                return getProfilePropertiesFromConfigFile(profileName, awsProfilesConfigFile);
            }
        }
        throw new FileNotFoundException("No config file ($HOME/.okta-config.properties and config.properties) found");
    }

    private static Properties getProfilePropertiesFromConfigFile(String profileName,
            ProfilesConfigFile awsProfilesConfigFile) {
        BasicProfile profile = awsProfilesConfigFile.getAllBasicProfiles().get(profileName);
        String oktaOrg = profile.getPropertyValue("OKTA_ORG");
        String oktaAwsAppUrl = profile.getPropertyValue("OKTA_AWS_APP_URL");
        String oktaUserName = profile.getPropertyValue("OKTA_USERNAME");

        String method = profile.getPropertyValue("OKTA_AUTH_METHOD");
        if (method == null) {
            method = "none";
        }
        OktaFactor oktaAuthMethod = OktaFactor.valueOf(method);

        String oktaAwsIamKey = profile.getPropertyValue("AWS_IAM_KEY");
        String oktaAwsIamSecret = profile.getPropertyValue("AWS_IAM_SECRET");

        if (StringUtils.isNullOrEmpty(oktaOrg) || StringUtils.isNullOrEmpty(oktaAwsAppUrl)) {
            System.err.println(String.format("Okta configuration does not exist, or is incomplete, for '%s' profile."
                    + " Please check your okta config file for errors. Will try to use default configuration.", profileName));
            System.exit(1);
        }

        Properties properties = new Properties();
        properties.put("OKTA_ORG", oktaOrg);
        properties.put("OKTA_AWS_APP_URL", oktaAwsAppUrl);

        if (oktaUserName != null && !oktaUserName.isEmpty()) {
            properties.put("OKTA_USERNAME", oktaUserName);
        }

        if (oktaAuthMethod != none) {
            properties.put("OKTA_AUTH_METHOD", oktaAuthMethod.name());
        }

        properties.put("AWS_IAM_KEY", oktaAwsIamKey);
        properties.put("AWS_IAM_SECRET", oktaAwsIamSecret);
        return properties;
    }

    /*Handles possible authentication failures */
    private static void authnFailHandler(int responseStatus, CloseableHttpResponse response) throws IOException {
        if (responseStatus == 200) {
            return;
        }

        String responseBody = responseBodyToString(response);

        StringBuffer messageBuffer = new StringBuffer();
        messageBuffer.append("The Okta server returned HTTP status code " + responseStatus + ".\n");
        if (responseStatus == 401) {
            messageBuffer.append("This is likely an authentication failure due to invalid credentials. The response body is:\n");
            messageBuffer.append(responseBody);
            if (null == cli) {
                logger.error(messageBuffer.toString());
                return;
            }
        } else if ((responseStatus >= 400) && (responseStatus < 500)) {
            messageBuffer.append("This is likely due to a bad request. The response body is:\n");
            messageBuffer.append(responseBody);
            if (null == cli) {
                logger.error(messageBuffer.toString());
                return;
            }
        } else if (responseStatus < 600) {
            messageBuffer.append("This is likely due to an server error. The response body is:\n");
            messageBuffer.append(responseBody);
            if (null == cli) {
                logger.error(messageBuffer.toString());
                System.exit(0);
            }
        } else {
            messageBuffer.append("This is an unrecognized error. The response body is:\n");
            messageBuffer.append(responseBody);
        }

        throw new RuntimeException(messageBuffer.toString());
    }

    /*Handles possible AWS assertion retrieval errors */
    private static void samlFailHandler(int requestStatus, CloseableHttpResponse responseSAML) throws UnknownHostException {
        if (responseSAML.getStatusLine().getStatusCode() == 500) {
            //incorrectly formatted app url
            throw new UnknownHostException();
        } else if (responseSAML.getStatusLine().getStatusCode() != 200) {
            //other
            throw new RuntimeException("Failed : HTTP error code : "
                    + responseSAML.getStatusLine().getStatusCode());
        }
    }

    /* Handles user selection prompts */
    private static int numSelection(int max) {
        int selection = -1;

        Scanner scanner = new Scanner(System.in, "UTF-8");
        while (selection == -1) {
            //prompt user for selection
            System.out.print("Selection: ");
            String selectInput = scanner.nextLine();
            try {
                selection = Integer.parseInt(selectInput) - 1;
                if (selection >= max) {
                    InputMismatchException e = new InputMismatchException();
                    throw e;
                }
            } catch (InputMismatchException e) {
                //raised by something other than a number entered
                logger.error("Invalid input: Please enter a number corresponding to a role \n");
                selection = -1;
            } catch (NumberFormatException e) {
                //raised by number too high or low selected
                logger.error("Invalid input: Please enter in a number \n");
                selection = -1;
            }
        }
        return selection;
    }

    /* Retrieves SAML assertion from Okta containing AWS roles */
    private static String awsSamlHandler(String oktaSessionToken) throws ClientProtocolException, IOException {
        HttpGet httpget = null;
        CloseableHttpResponse responseSAML = null;

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            String resultSAML = "";
            String outputSAML = "";

            // Part 2: Get the Identity Provider and Role ARNs.
            // Request for AWS SAML response containing roles
            httpget = new HttpGet(oktaAWSAppURL + "?onetimetoken=" + oktaSessionToken);
            responseSAML = httpClient.execute(httpget);
            samlFailHandler(responseSAML.getStatusLine().getStatusCode(), responseSAML);

            //Parse SAML response
            try (BufferedReader brSAML = new BufferedReader(new InputStreamReader(
                    (responseSAML.getEntity().getContent()), UTF_8))) {

                while ((outputSAML = brSAML.readLine()) != null) {
                    if (outputSAML.contains("SAMLResponse")) {
                        resultSAML = outputSAML.substring(outputSAML.indexOf("value=") + 7, outputSAML.indexOf("/>") - 1);
                        break;
                    }
                }
            }
            return resultSAML;
        }
    }


    /* Assumes SAML role selected by the user based on authorized Okta AWS roles given in SAML assertion result SAML
     * Precondition: String resultSAML
     * Postcondition: returns type AssumeRoleWithSAMLResult
     */
    private static AssumeRoleWithSAMLResult assumeAWSRole(String resultSAML) {
        // Decode SAML response
        resultSAML = resultSAML.replace("&#x2b;", "+").replace("&#x3d;", "=");
        String resultSAMLDecoded = new String(Base64.decodeBase64(resultSAML), UTF_8);

        ArrayList<String> principalArns = new ArrayList<String>();
        ArrayList<String> roleArns = new ArrayList<String>();

        //When the app is not assigned to you no assertion is returned
        if (!resultSAMLDecoded.contains("arn:aws")) {
            logger.error("\nYou do not have access to AWS through Okta. \nPlease contact your administrator.");
            System.exit(0);
        }

        if ((null != cli) && cli.hasOption(ROLE_OPT)) {
            String cliRole = cli.getOptionValue(ROLE_OPT);
            String[] parts = findMatchingRole(resultSAMLDecoded, cliRole);
            if (null == parts) {
                System.out.println(String.format(
                        "You are not allowed to assume the '%s' role. Either you don't have permission or there is a typographical error in your input.",
                        cliRole));
                System.exit(1);
            }
            String principalArn = parts[0];
            String roleArn = parts[1];
            return awsStsAssumeRoleWithSaml(resultSAML, principalArn, roleArn);
        }

        System.out.println("\nPlease choose the role you would like to assume: ");

        //Gather list of applicable AWS roles
        int i = 0;
        while (resultSAMLDecoded.indexOf("arn:aws") != -1) {
            /*Trying to parse the value of the Role SAML Assertion that typically looks like this:
            <saml2:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">
            arn:aws:iam::[AWS-ACCOUNT-ID]:saml-provider/Okta,arn:aws:iam::[AWS-ACCOUNT-ID]:role/[ROLE_NAME]
            </saml2:AttributeValue>
      </saml2:Attribute>
            */
            int start = resultSAMLDecoded.indexOf("arn:aws");
            int end = resultSAMLDecoded.indexOf("</saml2:", start);
            String resultSAMLRole = resultSAMLDecoded.substring(start, end);
            String[] parts = resultSAMLRole.split(",");
            principalArns.add(parts[0]);
            roleArns.add(parts[1]);
            System.out.println("[ " + (i + 1) + " ]: " + roleArns.get(i));
            resultSAMLDecoded = (resultSAMLDecoded.substring(resultSAMLDecoded.indexOf("</saml2:AttributeValue") + 1));
            i++;
        }

        int selection = 0;
        if (i > 1) {
            //Prompt user for role selection
            selection = numSelection(roleArns.size());
        } else {
            System.out.println("Selected only role presented.");
        }

        String principalArn = principalArns.get(selection);
        String roleArn = roleArns.get(selection);
        crossAccountRoleName = roleArn.substring(roleArn.indexOf("/") + 1);
        logger.debug("Cross-account role is " + crossAccountRoleName);

        return awsStsAssumeRoleWithSaml(resultSAML, principalArn, roleArn);
    }

    private static AssumeRoleWithSAMLResult awsStsAssumeRoleWithSaml(String resultSAML, String principalArn,
            String roleArn) {
        //creates empty AWS credentials to prevent the AWSSecurityTokenServiceClient object from unintentionally loading the previous profile we just created
        BasicAWSCredentials awsCreds = new BasicAWSCredentials("", "");

        //use user credentials to assume AWS role
        AWSSecurityTokenServiceClient stsClient = new AWSSecurityTokenServiceClient(awsCreds);

        AssumeRoleWithSAMLRequest assumeRequest = new AssumeRoleWithSAMLRequest()
                .withPrincipalArn(principalArn)
                .withRoleArn(roleArn)
                .withSAMLAssertion(resultSAML)
                .withDurationSeconds(3600); //default token duration to 12 hours

        return stsClient.assumeRoleWithSAML(assumeRequest);
    }

    private static String[] findMatchingRole(String resultSAMLDecoded, String role) {
        while (resultSAMLDecoded.indexOf("arn:aws") != -1) {
            int start = resultSAMLDecoded.indexOf("arn:aws");
            int end = resultSAMLDecoded.indexOf("</saml2:", start);
            String resultSAMLRole = resultSAMLDecoded.substring(start, end);
            String[] parts = resultSAMLRole.split(",");
            String roleArn = parts[1];
            if (roleArn.equalsIgnoreCase(role) || roleArn.toLowerCase().endsWith("/" + role.toLowerCase())) {
                return parts;
            }
            resultSAMLDecoded = (resultSAMLDecoded.substring(resultSAMLDecoded.indexOf("</saml2:AttributeValue") + 1));
        }
        return null;
    }

    private static void GetRoleToAssume(String roleName) {

        if (roleName != null && !roleName.equals("") && awsIamKey != null && awsIamSecret != null && !awsIamKey.equals("") && !awsIamSecret.equals("")) {

            logger.debug("Creating the AWS Identity Management client");
            AmazonIdentityManagementClient identityManagementClient
                    = new AmazonIdentityManagementClient(new BasicAWSCredentials(awsIamKey, awsIamSecret));

            logger.debug("Getting role: " + roleName);
            GetRoleResult roleresult = identityManagementClient.getRole(new GetRoleRequest().withRoleName(roleName));
            logger.debug("GetRoleResult: " + roleresult.toString());
            Role role = roleresult.getRole();
            logger.debug("getRole: " + role.toString());
            ListAttachedRolePoliciesResult arpr = identityManagementClient
                    .listAttachedRolePolicies(new ListAttachedRolePoliciesRequest().withRoleName(roleName));
            logger.debug("ListAttachedRolePoliciesResult: " + arpr.toString());
            ListRolePoliciesResult lrpr = identityManagementClient.listRolePolicies(new ListRolePoliciesRequest().withRoleName(roleName));
            logger.debug("ListRolePoliciesResult: " + lrpr.toString());

            List<String> inlinePolicies = lrpr.getPolicyNames();
            if (inlinePolicies.size() == 0) {
                logger.debug("There are no inlines policies");
            }
            List<AttachedPolicy> managedPolicies = arpr.getAttachedPolicies();
            if (managedPolicies.size() == 0) {
                logger.debug("There are no managed policies");
            }

            selectedPolicyRank = 0; //by default, we select the first policy

            if (managedPolicies.size() >= 1) //we prioritize managed policies over inline policies
            {
                if (managedPolicies.size() > 1) //if there's more than one policy, we're asking the user to select one of them
                {
                    List<String> lstManagedPolicies = new ArrayList<String>();

                    for (AttachedPolicy managedPolicy : managedPolicies) {
                        lstManagedPolicies.add(managedPolicy.getPolicyName());
                    }

                    logger.debug("Managed Policies: " + managedPolicies.toString());

                    selectedPolicyRank = SelectPolicy(lstManagedPolicies);
                }

                AttachedPolicy attachedPolicy = managedPolicies.get(selectedPolicyRank);
                logger.debug("Selected policy " + attachedPolicy.toString());
                GetPolicyRequest gpr = new GetPolicyRequest().withPolicyArn(attachedPolicy.getPolicyArn());

                GetPolicyResult rpr = identityManagementClient.getPolicy(gpr);
                logger.debug("GetPolicyResult: " + attachedPolicy.toString());
                Policy policy = rpr.getPolicy();

                GetPolicyVersionResult pvr = identityManagementClient
                        .getPolicyVersion(new GetPolicyVersionRequest().withPolicyArn(policy.getArn()).withVersionId(policy.getDefaultVersionId()));
                logger.debug("GetPolicyVersionResult: " + pvr.toString());

                String policyDoc = pvr.getPolicyVersion().getDocument();

                roleToAssume = ProcessPolicyDocument(policyDoc);
            } else if (inlinePolicies.size() >= 1) //processing inline policies if we have no managed policies
            {
                logger.debug("Inline Policies " + inlinePolicies.toString());

                if (inlinePolicies.size() > 1) {
                    //ask the user to select one policy if there are more than one

                    logger.debug("Inline Policies: " + inlinePolicies.toString());

                    selectedPolicyRank = SelectPolicy(inlinePolicies);
                }

                //Have to set the role name and the policy name (both are mandatory fields
                //TODO: handle more than 1 policy (ask the user to choose it?)
                GetRolePolicyRequest grpr = new GetRolePolicyRequest().withRoleName(roleName).withPolicyName(inlinePolicies.get(selectedPolicyRank));
                GetRolePolicyResult rpr = identityManagementClient.getRolePolicy(grpr);
                String policyDoc = rpr.getPolicyDocument();

                roleToAssume = ProcessPolicyDocument(policyDoc);
            }
        }
    }

    private static int SelectPolicy(List<String> lstPolicies) {
        System.out.println("\nPlease select a role policy: ");

        // Gather list of policies for the selected role
        int i = 1;
        for (String strPolicyName : lstPolicies) {
            System.out.println("[ " + i + " ]: " + strPolicyName);
            i++;
        }

        // Prompt user for policy selection
        return numSelection(lstPolicies.size());
    }

    private static String ProcessPolicyDocument(String policyDoc) {

        String strRoleToAssume = null;
        try {
            String policyDocClean = URLDecoder.decode(policyDoc, "UTF-8");
            logger.debug("Clean Policy Document: " + policyDocClean);
            ObjectMapper objectMapper = new ObjectMapper();

            try {
                JsonNode rootNode = objectMapper.readTree(policyDocClean);
                JsonNode statement = rootNode.path("Statement");
                logger.debug("Statement node: " + statement.toString());
                JsonNode resource = null;
                if (statement.isArray()) {
                    logger.debug("Statement is array");
                    for (int i = 0; i < statement.size(); i++) {
                        String action = statement.get(i).path("Action").textValue();
                        if (action != null && action.equals("sts:AssumeRole")) {
                            resource = statement.get(i).path("Resource");
                            logger.debug("Resource node: " + resource.toString());
                            break;
                        }
                    }
                } else {
                    logger.debug("Statement is NOT array");
                    if (statement.get("Action").textValue().equals("sts:AssumeRole")) {
                        resource = statement.path("Resource");
                        logger.debug("Resource node: " + resource.toString());
                    }
                }
                if (resource != null) {
                    if (resource.isArray()) { //if we're handling a policy with an array of AssumeRole attributes
                        ArrayList<String> lstRoles = new ArrayList<String>();
                        for (final JsonNode node : resource) {
                            lstRoles.add(node.asText());
                        }
                        strRoleToAssume = SelectRole(lstRoles);
                    } else {
                        strRoleToAssume = resource.textValue();
                        logger.debug("Role to assume: " + roleToAssume);
                    }
                }
            } catch (IOException ioe) {
            }
        } catch (UnsupportedEncodingException uee) {

        }
        return strRoleToAssume;
    }

    /* Prompts the user to select a role in case the role policy contains an array of roles instead of a single role
     */
    private static String SelectRole(List<String> lstRoles) {
        String strSelectedRole = null;

        System.out.println("\nPlease select the role you want to assume: ");

        //Gather list of roles for the selected managed policy
        int i = 1;
        for (String strRoleName : lstRoles) {
            System.out.println("[ " + i + " ]: " + strRoleName);
            i++;
        }

        //Prompt user for policy selection
        int selection = numSelection(lstRoles.size());

        if (selection < 0 && lstRoles.size() > selection) {
            System.out.println("\nYou entered an invalid number. Please try again.");
            return SelectRole(lstRoles);
        }

        strSelectedRole = lstRoles.get(selection);

        return strSelectedRole;
    }

    /* Retrieves AWS credentials from AWS's assumedRoleResult and write the to aws credential file
     * Precondition :  AssumeRoleWithSAMLResult assumeResult
     */
    private static void setAWSCredentials(AssumeRoleWithSAMLResult assumeResult, String credentialsProfileName)
            throws FileNotFoundException, UnsupportedEncodingException, IOException {
        BasicSessionCredentials temporaryCredentials =
                new BasicSessionCredentials(
                        assumeResult.getCredentials().getAccessKeyId(),
                        assumeResult.getCredentials().getSecretAccessKey(),
                        assumeResult.getCredentials().getSessionToken());

        String awsAccessKey = temporaryCredentials.getAWSAccessKeyId();
        String awsSecretKey = temporaryCredentials.getAWSSecretKey();
        String awsSessionToken = temporaryCredentials.getSessionToken();

        // Update the credentials file with the unique profile name
        UpdateCredentialsFile(credentialsProfileName, awsAccessKey, awsSecretKey, awsSessionToken);
    }

    private static String createDefaultProfileName(String credentialsProfileName) {
        if (credentialsProfileName.startsWith("arn:aws:sts::")) {
            credentialsProfileName = credentialsProfileName.substring(13);
        }
        if (credentialsProfileName.contains(":assumed-role")) {
            credentialsProfileName = credentialsProfileName.replaceAll(":assumed-role", "");
        }

        Object[] messageArgs = {credentialsProfileName, selectedPolicyRank};
        MessageFormat profileNameFormat = new MessageFormat("{0}/{1}");
        credentialsProfileName = profileNameFormat.format(messageArgs);

        return credentialsProfileName;
    }

    private static void UpdateCredentialsFile(String profileName, String awsAccessKey, String awsSecretKey, String awsSessionToken)
            throws IOException {

        ProfilesConfigFile profilesConfigFile = null;

        try {
            profilesConfigFile = new ProfilesConfigFile();
        } catch (AmazonClientException ace) {
            PopulateCredentialsFile(profileName, awsAccessKey, awsSecretKey, awsSessionToken);
        }

        try {
            if (profilesConfigFile != null && profilesConfigFile.getCredentials(profileName) != null) {
                //if we end up here, it means we were  able to find a matching profile
                PopulateCredentialsFile(profileName, awsAccessKey, awsSecretKey, awsSessionToken);
            }
        } catch (AmazonClientException ace) {
            //this could happen if the default profile doesn't have a valid AWS Access Key ID
            //in this case, error would be "Unable to load credentials into profile [default]: AWS Access Key ID is not specified."
            PopulateCredentialsFile(profileName, awsAccessKey, awsSecretKey, awsSessionToken);
        } catch (IllegalArgumentException iae) {
            //if we end up here, it means we were not able to find a matching profile so we need to append one
            PopulateCredentialsFile(profileName, awsAccessKey, awsSecretKey, awsSessionToken);
        }
    }

    private static void PopulateCredentialsFile(String profileName, String awsAccessKey, String awsSecretKey,
            String awsSessionToken) throws IOException {

        File credentialsFile = new File(System.getProperty("user.home") + "/.aws/credentials");

        Map<String, String> properties = new HashMap<>();
        properties.put(ProfileKeyConstants.AWS_ACCESS_KEY_ID, awsAccessKey);
        properties.put(ProfileKeyConstants.AWS_SECRET_ACCESS_KEY, awsSecretKey);
        properties.put(ProfileKeyConstants.AWS_SESSION_TOKEN, awsSessionToken);
        properties.put("aws_security_token", awsSessionToken);

        BasicProfile awsCredentialsProfile = new BasicProfile(profileName, properties);
        BackwardCompatibleProfilesConfigFileWriter.modifyOneProfile(credentialsFile, profileName,
                SdkProfilesFactory.convert(awsCredentialsProfile));
    }

    private static void UpdateConfigFile(String profileName, String roleToAssume) throws IOException {

        File inFile = new File(System.getProperty("user.home") + "/.aws/config");

        FileInputStream fis = new FileInputStream(inFile);
        BufferedReader br = new BufferedReader(new InputStreamReader(fis, US_ASCII));
        File tempFile = new File(inFile.getAbsolutePath() + ".tmp");

        PrintWriter pw = new PrintWriter(new BufferedWriter(new OutputStreamWriter(new FileOutputStream(tempFile), US_ASCII)));

        String line = null;
        boolean profileExists = false;

        // Search for an existing profile but don't touch the file.
        while ((line = br.readLine()) != null) {
            if (line.contains(profileName)) {
                profileExists = true;
            }

            pw.println(line);
        }

        // If there is no existing profile, then write configuration for the new profile.
        if (!profileExists) {
            writeNewRoleToAssume(pw, profileName, roleToAssume);
        }

        pw.flush();
        pw.close();
        br.close();

        //delete the original credentials file
        if (!inFile.delete()) {
            System.out.println("Could not delete original config file");
        } else {
            // Rename the new file to the filename the original file had.
            if (!tempFile.renameTo(inFile)) {
                System.out.println("Could not rename file");
            }
        }
    }

    public static void writeNewProfile(PrintWriter pw, String profileNameLine, String awsAccessKey, String awsSecretKey,
            String awsSessionToken) {
        pw.println(profileNameLine);
        pw.println("aws_access_key_id=" + awsAccessKey);
        pw.println("aws_secret_access_key=" + awsSecretKey);
        pw.println("aws_session_token=" + awsSessionToken);
        // Some older libraries (in particular boto2, used by ansible) look for
        // Amazon's session token under variable named `aws_security_token`,
        // rather than `aws_session_token`.
        pw.println("aws_security_token=" + awsSessionToken);
    }

    public static void writeNewRoleToAssume(PrintWriter pw, String profileName, String roleToAssume) {

        pw.println("[profile " + profileName + "]");
        if (roleToAssume != null && !roleToAssume.equals("")) {
            pw.println("role_arn=" + roleToAssume);
        }
        pw.println("source_profile=" + profileName);
        pw.println("region=us-east-1");
    }

    private static String mfa(JSONObject authResponse) {

        try {
            //User selects which factor to use
            JSONObject factor = selectFactor(authResponse);
            String factorType = factor.getString("factorType");
            String stateToken = authResponse.getString("stateToken");

            //factor selection handler
            switch (factorType) {
                case ("question"): {
                    //question factor handler
                    String sessionToken = questionFactor(factor, stateToken);
                    if (sessionToken.equals("change factor")) {
                        System.out.println("Factor Change Initiated");
                        return mfa(authResponse);
                    }
                    return sessionToken;
                }
                case ("sms"): {
                    //sms factor handler
                    String sessionToken = smsFactor(factor, stateToken);
                    if (sessionToken.equals("change factor")) {
                        System.out.println("Factor Change Initiated");
                        return mfa(authResponse);
                    }
                    return sessionToken;

                }
                case ("token:software:totp"): {
                    //token factor handler
                    String sessionToken = totpFactor(factor, stateToken);
                    if (sessionToken.equals("change factor")) {
                        System.out.println("Factor Change Initiated");
                        return mfa(authResponse);
                    }
                    return sessionToken;
                }
                case ("push"): {
                    //push factor handles
                    String result = pushFactor(factor, stateToken);
                    if (result.equals("timeout") || result.equals("change factor")) {
                        return mfa(authResponse);
                    }
                    return result;
                }
            }
        } catch (JSONException e) {
            e.printStackTrace();
        } catch (ClientProtocolException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        return "";
    }


    /*Handles factor selection based on factors found in parameter authResponse, returns the selected factor
     * Precondition: JSINObject authResponse
     * Postcondition: return session token as String sessionToken
     */
    public static JSONObject selectFactor(JSONObject authResponse) throws JSONException {
        JSONArray factors = authResponse.getJSONObject("_embedded").getJSONArray("factors");

        if ((cli != null) && cli.hasOption(SECOND_FACTOR_TYPE_OPT)) {
            String cliFactorType = cli.getOptionValue(SECOND_FACTOR_TYPE_OPT).toLowerCase();
            if (!SUPPORTED_2FA.contains(cliFactorType)) {
                printUsage();
            }

            // Find the requested TOTP second factor of authentication.
            for (int i = 0; i < factors.length(); i++) {
                JSONObject factor = factors.getJSONObject(i);
                String factorType = factor.getString("factorType");
                if (factorType.equals("token:software:totp")) {
                    String provider = factor.getString("provider");
                    if (provider.equalsIgnoreCase(cliFactorType)) {
                        return factor;
                    }
                }
            }

            System.out.println(String.format("The configured identity provider does not support '%s' as a second factor of authentication.", cliFactorType));
            System.exit(1);
        }

        System.out.println("\nMulti-Factor authentication is required. Please select a factor to use.");
        //list factor to select from to user
        int selection = -1;
        System.out.println("Factors:");
        for (int i = 0; i < factors.length(); i++) {
            JSONObject factor = factors.getJSONObject(i);
            String factorType = factor.getString("factorType");
            if (factorType.equals("question")) {
                factorType = "Security Question";
                if (oktaAuthMethod == question) {
                    selection = i;
                }
            } else if (factorType.equals("sms")) {
                factorType = "SMS Authentication";
                if (oktaAuthMethod == sms) {
                    selection = i;
                }
            } else if (factorType.equals("token:software:totp")) {
                String provider = factor.getString("provider");
                if (provider.equals("GOOGLE")) {
                    factorType = "Google Authenticator";
                    if (oktaAuthMethod == google) {
                        selection = i;
                    }
                } else {
                    factorType = "Okta Verify";
                    if (oktaAuthMethod == okta_verify) {
                        selection = i;
                    }
                }
            }
            System.out.println("[ " + (i + 1) + " ] : " + factorType);
        }

        if (selection == -1) {
            //Handles user factor selection
            selection = numSelection(factors.length());
        } else {
            System.out.printf("Selected %d from profile%n", selection + 1);
        }
        return factors.getJSONObject(selection);
    }


    private static String questionFactor(JSONObject factor, String stateToken) throws JSONException, ClientProtocolException, IOException {
        String question = factor.getJSONObject("profile").getString("questionText");
        Scanner scanner = new Scanner(System.in, "UTF-8");
        String sessionToken = "";
        String answer = "";

        //prompt user for answer
        System.out.println("\nSecurity Question Factor Authentication\nEnter 'change factor' to use a different factor\n");
        while ((null == sessionToken) || "".equals(sessionToken)) {
            if (answer != "") {
                System.out.println("Please try again");
            }
            System.out.println(question);
            System.out.print("Answer: ");
            answer = scanner.nextLine();
            //verify answer is correct
            if (answer.toLowerCase().equals("change factor")) {
                return answer;
            }
            sessionToken = verifyAnswer(answer, factor, stateToken, "question");
        }
        return sessionToken;
    }


    /*Handles sms factor authentication
     * Precondition: question factor as JSONObject factor, current state token stateToken
     * Postcondition: return session token as String sessionToken
     */
    private static String smsFactor(JSONObject factor, String stateToken) throws ClientProtocolException, JSONException, IOException {
        if ((null != cli) && cli.hasOption(SECOND_FACTOR_TOKEN_OPT)) {
            return verifyAnswer(cli.getOptionValue(SECOND_FACTOR_TOKEN_OPT), factor, stateToken, "sms");
        }

        Scanner scanner = new Scanner(System.in, "UTF-8");
        String answer = "";
        String sessionToken = "";

        //prompt for sms verification
        System.out.println("\nSMS Factor Authentication \nEnter 'change factor' to use a different factor");
        while ((null == sessionToken) || "".equals(sessionToken)) {
            if (answer != "") {
                System.out.println("Please try again or type 'new code' to be sent a new sms token");
            } else {
                //send initial code to user
                sessionToken = verifyAnswer("", factor, stateToken, "sms");
            }
            System.out.print("SMS Code: ");
            answer = scanner.nextLine();
            //resends code
            if (answer.equals("new code")) {
                answer = "";
                System.out.println("New code sent! \n");
            } else if (answer.toLowerCase().equals("change factor")) {
                return answer;
            }
            //verifies code
            sessionToken = verifyAnswer(answer, factor, stateToken, "sms");
        }
        return sessionToken;
    }


    /*
     * Handles token factor authentication, i.e: Google Authenticator or Okta Verify
     *  Precondition: question factor as JSONObject factor, current state token stateToken
     *  Postcondition: return session token as String sessionToken
     */
    private static String totpFactor(JSONObject factor, String stateToken) throws ClientProtocolException, JSONException, IOException {
        if ((null != cli) && cli.hasOption(SECOND_FACTOR_TOKEN_OPT)) {
            return verifyAnswer(cli.getOptionValue(SECOND_FACTOR_TOKEN_OPT), factor, stateToken, "token:software:totp");
        }

        Scanner scanner = new Scanner(System.in, "UTF-8");
        String sessionToken = "";
        String answer = "";

        //prompt for token
        System.out.println("\n" + factor.getString("provider") + " Token Factor Authentication\nEnter 'change factor' to use a different factor");
        while ((null == sessionToken) || "".equals(sessionToken)) {
            if (answer != "") {
                System.out.println("Please try again");
            }

            System.out.print("Token: ");
            answer = scanner.nextLine();
            //verify auth Token
            if (answer.toLowerCase().equals("change factor")) {
                return answer;
            }
            sessionToken = verifyAnswer(answer, factor, stateToken, "token:software:totp");
        }
        return sessionToken;
    }

    /* Handles push factor authentication
     *
     *
     */
    private static String pushFactor(JSONObject factor, String stateToken) throws ClientProtocolException, JSONException, IOException {
        String sessionToken = "";

        System.out.println("\nPush Factor Authentication");
        while ((null == sessionToken) || "".equals(sessionToken)) {
            //Verify if Okta Push has been pushed
            sessionToken = verifyAnswer(null, factor, stateToken, "push");
            System.out.println(sessionToken);
            if (sessionToken.equals("Timeout")) {
                System.out.println("Session has timed out");
                return "timeout";
            }
        }
        return sessionToken;
    }


    /*Handles verification for all Factor types
     * Precondition: question factor as JSONObject factor, current state token stateToken
     * Postcondition: return session token as String sessionToken
     */
    private static String verifyAnswer(String answer, JSONObject factor, String stateToken, String factorType)
            throws JSONException, ClientProtocolException, IOException {

        String sessionToken = null;

        JSONObject profile = new JSONObject();
        String verifyPoint = factor.getJSONObject("_links").getJSONObject("verify").getString("href");

        profile.put("stateToken", stateToken);

        JSONObject jsonObjResponse = null;

        if (answer != null && answer != "") {
            profile.put("answer", answer);
        }

        //create post request
        CloseableHttpResponse responseAuthenticate = null;
        CloseableHttpClient httpClient = HttpClients.createDefault();

        HttpPost httpost = new HttpPost(verifyPoint);
        httpost.addHeader("Accept", "application/json");
        httpost.addHeader("Content-Type", "application/json");
        httpost.addHeader("Cache-Control", "no-cache");

        StringEntity entity = new StringEntity(profile.toString(), UTF_8);
        entity.setContentType("application/json");
        httpost.setEntity(entity);
        responseAuthenticate = httpClient.execute(httpost);

        String outputAuthenticate = responseBodyToString(responseAuthenticate);
        jsonObjResponse = new JSONObject(outputAuthenticate);

        if (jsonObjResponse.has("errorCode")) {
            String message = "MFA authentication failed with: " + jsonObjResponse.getString("errorSummary");
            if (null != cli) {
                throw new RuntimeException(message);
            }
            System.out.println(message);
            return null;
        }

        if (jsonObjResponse != null && jsonObjResponse.has("sessionToken")) {
            sessionToken = jsonObjResponse.getString("sessionToken");
        }

        String pushResult = null;
        if (factorType.equals("push")) {
            if (jsonObjResponse.has("_links")) {
                JSONObject linksObj = jsonObjResponse.getJSONObject("_links");

                //JSONObject pollLink = links.getJSONObject("poll");
                JSONArray names = linksObj.names();
                JSONArray links = linksObj.toJSONArray(names);
                String pollUrl = "";
                for (int i = 0; i < links.length(); i++) {
                    JSONObject link = links.getJSONObject(i);
                    String linkName = link.getString("name");
                    if (linkName.equals("poll")) {
                        pollUrl = link.getString("href");
                        break;
                        //System.out.println("[ " + (i+1) + " ] :" + factorType );
                    }
                }

                while (pushResult == null || pushResult.equals("WAITING")) {
                    pushResult = null;
                    CloseableHttpResponse responsePush = null;
                    httpClient = HttpClients.createDefault();

                    HttpPost pollReq = new HttpPost(pollUrl);
                    pollReq.addHeader("Accept", "application/json");
                    pollReq.addHeader("Content-Type", "application/json");
                    pollReq.addHeader("Cache-Control", "no-cache");

                    entity = new StringEntity(profile.toString(), UTF_8);
                    entity.setContentType("application/json");
                    pollReq.setEntity(entity);

                    responsePush = httpClient.execute(pollReq);

                    try (BufferedReader br = new BufferedReader(new InputStreamReader((responsePush.getEntity().getContent()), UTF_8))) {

                        String outputTransaction = br.readLine();
                        JSONObject jsonTransaction = new JSONObject(outputTransaction);

                        if (jsonTransaction.has("factorResult")) {
                            pushResult = jsonTransaction.getString("factorResult");
                        }

                        if (pushResult == null && jsonTransaction.has("status")) {
                            pushResult = jsonTransaction.getString("status");
                        }

                        System.out.println("Waiting for you to approve the Okta push notification on your device...");
                        try {
                            Thread.sleep(500);
                        } catch (InterruptedException iex) {

                        }

                        if (jsonTransaction.has("sessionToken")) {
                            sessionToken = jsonTransaction.getString("sessionToken");
                        }
                    }
                }
            }
        }

        if (sessionToken != null) {
            return sessionToken;
        } else {
            return pushResult;
        }
    }

    /* prints final status message to user */
    private static void resultMessage(String profileName) {
        Calendar date = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat();
        date.add(Calendar.HOUR, 1);

        //change with file customization
        System.out.println("\n----------------------------------------------------------------------------------------------------------------------");
        System.out.println("Your new access key pair has been stored in the aws configuration file with the following profile name: " + profileName);
        System.out.println("The AWS Credentials file is located in " + System.getProperty("user.home") + "/.aws/credentials.");
        System.out.println("Note that it will expire at " + dateFormat.format(date.getTime()));
        System.out.println("After this time you may safely rerun this script to refresh your access key pair.");
        System.out.println("To use these credentials, please call the aws cli with the --profile option "
                + "(e.g. aws --profile " + profileName + " ec2 describe-instances)");
        System.out.println("You can also omit the --profile option to use the last configured profile "
                + "(e.g. aws s3 ls)");
        System.out.println("----------------------------------------------------------------------------------------------------------------------");
    }

    private static Options createCliOptions() {
        Options options = new Options();
        options.addOption(Option.builder(PROFILE_OPT).argName("profile").longOpt("profile").hasArg(true)
                .desc("The AWS profile used to write configuration and credentials on success.")
                .required(false).build());
        options.addOption(Option.builder(ROLE_OPT).argName("role").longOpt("role").hasArg(true)
                .desc("The AWS role to assume upon authentication success. "
                        + "NOTE: if you enter a role that you are not allowed to assume the login will fail.")
                .required(false).build());
        options.addOption(Option.builder(USERNAME_OPT).argName("username").longOpt("username").hasArg(true)
                .desc("The SSO username used for Okta authentication.")
                .required(false).build());
        options.addOption(Option.builder(PASSWORD_OPT).argName("password").longOpt("password").hasArg(true)
                .desc("The SSO password used for Okta authentication. "
                        + "WARNING: remember to clear your shell history if you use this option!")
                .required(false).build());
        options.addOption(Option.builder(SECOND_FACTOR_TYPE_OPT).argName("2fa-type").longOpt("2fa-type").hasArg(true)
                .desc("An desired type of second factor authentication."
                        + " Currently, this tool only supports 'google' as a non-interactive second factor of authentication.")
                .required(false).build());
        options.addOption(Option.builder(SECOND_FACTOR_TOKEN_OPT).argName("2fa-token").longOpt("2fa-token").hasArg(true)
                .desc("The token for the second factor of authentication.")
                .required(false).build());
        return options;
    }
}
