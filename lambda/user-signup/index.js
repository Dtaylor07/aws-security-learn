'use strict';

/**
 * Cognito PostConfirmation Lambda Trigger
 * ───────────────────────────────────────
 * Fired when a user confirms their account (email verification).
 * 1. Stores user profile in DynamoDB (private VPC subnet via VPC endpoint)
 * 2. Publishes a USER_SIGNUP event to EventBridge
 *
 * Exam relevance:
 *  - Domain 4 (IAM): Lambda execution role with least-privilege
 *  - Domain 5 (Data): DynamoDB encryption at rest via KMS CMK
 *  - Domain 1 (Detection): EventBridge rule + CloudWatch Logs
 *  - Domain 3 (Infra): Lambda in VPC with VPC endpoint for DynamoDB
 */

const { DynamoDBClient, PutItemCommand } = require('@aws-sdk/client-dynamodb');
const { EventBridgeClient, PutEventsCommand } = require('@aws-sdk/client-eventbridge');
const { createLogger, format, transports } = require('winston');

const logger = createLogger({
  level: 'info',
  format: format.combine(format.timestamp(), format.json()),
  transports: [new transports.Console()]
});

// Clients — Lambda execution role grants access; no credentials in code
const dynamo = new DynamoDBClient({ region: process.env.AWS_REGION || 'us-east-1' });
const events = new EventBridgeClient({ region: process.env.AWS_REGION || 'us-east-1' });

const TABLE_NAME   = process.env.DYNAMODB_TABLE_NAME   || 'secureapp-users';
const EVENT_BUS    = process.env.EVENT_BUS_NAME         || 'secureapp-events';
const EVENT_SOURCE = 'com.secureapp.cognito';

// ── Handler ───────────────────────────────────────────────────────────────────

exports.handler = async (event) => {
  const { userName, request, userPoolId } = event;
  const { userAttributes } = request;

  const userId  = userAttributes.sub;
  const email   = userAttributes.email || '';
  const name    = userAttributes.name  || userAttributes.preferred_username || '';
  const now     = new Date().toISOString();

  logger.info('user_signup_trigger', {
    userName,
    userId,
    email,
    userPoolId
  });

  try {
    // ── 1. Write user record to DynamoDB ────────────────────────────────────
    // Table uses KMS CMK for server-side encryption (SSE-KMS)
    // Lambda reaches DynamoDB via VPC Gateway Endpoint — no internet traversal
    await dynamo.send(new PutItemCommand({
      TableName: TABLE_NAME,
      Item: {
        userId:    { S: userId },
        email:     { S: email },
        name:      { S: name },
        userName:  { S: userName },
        userPoolId:{ S: userPoolId },
        createdAt: { S: now },
        status:    { S: 'ACTIVE' },
        // Never store passwords or tokens here
      },
      // Idempotency guard — do not overwrite if user already exists
      ConditionExpression: 'attribute_not_exists(userId)'
    }));

    logger.info('dynamodb_write_success', { userId, table: TABLE_NAME });

    // ── 2. Publish USER_SIGNUP event to EventBridge ─────────────────────────
    // Downstream consumers (notifications, analytics) subscribe to this event
    // EventBridge rule can also trigger GuardDuty investigation or SNS alert
    await events.send(new PutEventsCommand({
      Entries: [{
        Source:       EVENT_SOURCE,
        DetailType:   'UserSignUp',
        Detail: JSON.stringify({
          userId,
          email,
          name,
          userName,
          userPoolId,
          timestamp: now,
          // Never include PII beyond what's needed
        }),
        EventBusName: EVENT_BUS
      }]
    }));

    logger.info('eventbridge_published', {
      userId,
      eventBus: EVENT_BUS,
      detailType: 'UserSignUp'
    });

  } catch (err) {
    // Log error but still return the event to Cognito so sign-up completes
    // The user should not fail to confirm just because a downstream write failed
    logger.error('signup_handler_error', {
      userId,
      error: err.name,
      message: err.message
    });
  }

  // Must return the Cognito event unchanged for the trigger to succeed
  return event;
};
