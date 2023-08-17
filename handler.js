'use strict';
const serverless=require('serverless-http')
const app=require('.')
module.exports.hello =serverless(app)