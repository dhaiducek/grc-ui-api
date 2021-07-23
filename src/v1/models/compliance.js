/** *****************************************************************************
 * Licensed Materials - Property of IBM
 * (c) Copyright IBM Corporation 2018, 2019. All Rights Reserved.
 *
 * Note to U.S. Government Users Restricted Rights:
 * Use, duplication or disclosure restricted by GSA ADP Schedule
 * Contract with IBM Corp.
 ******************************************************************************* */
/* Copyright (c) 2020 Red Hat, Inc. */
/* Copyright Contributors to the Open Cluster Management project */

import { ApolloError } from 'apollo-errors';
import _ from 'lodash';
import logger from '../lib/logger';
import config from '../../../config';
import ApiGroup from '../lib/ApiGroup';
import getTypedNS from '../lib/getTypedNS';

const policyAPIPrefix = `/apis/${ApiGroup.policiesGroup}/${ApiGroup.version}/namespaces`;
const appAPIPrefix = `/apis/${ApiGroup.appsGroup}/${ApiGroup.version}/namespaces`;
const clusterAPIPrefix = `/apis/${ApiGroup.clusterInfoGroup}/${ApiGroup.clusterAPIVersion}/namespaces`;
const POLICY_FAILURE_STATUS = 'Failure';
const metadataNameStr = 'metadata.name';
const metadataNsStr = 'metadata.namespace';
const specReActionStr = 'spec.remediationAction';
const statusStatusStr = 'status.status';
const specRuntimeRulesStr = 'spec.runtime-rules';
const roleTemplatesStr = 'role-templates';
const roleBindingTemplatesStr = 'roleBinding-templates';
const objectTemplatesStr = 'object-templates';
const policyTemplatesStr = 'policy-templates';
const runtimeRulesStr = 'runtime-rules';
const statusLCompliantStr = 'status.compliant';
const statusUCompliantStr = 'status.Compliant';
const statusLastTransTimeStr = 'status.conditions[0].lastTransitionTime';
const statusValidityValidStr = 'status.Validity.valid';
const statusValidityStr = 'status.Validity';
const objMetadataNameStr = 'objectDefinition.metadata.name';
const statusDetails = 'status.details';
const templateMetaNameStr = 'templateMeta.name';
const historyLatestMessageStr = 'history[0].message';
const historyLatestTimestampStr = 'history[0].lastTimestamp';

function getTemplates(policy = {}, templateType = '') {
  const templates = [];
  Object.entries(policy.spec || []).forEach(([key, value]) => {
    if (key.endsWith(`${templateType}-templates`)) {
      value.forEach((item) => templates.push({ ...item, templateType: key }));
    }
  });
  return templates;
}

function createStatusResult(data) {
  const map = new Map();
  data.forEach((item) => {
    const { name, status } = item;
    if (!map.has(name)) {
      map.set(name, { name, total: 0, violated: 0 });
    }
    const exist = map.get(name);
    const { total, violated } = exist;
    map.set(name, { name, total: total + 1, violated: violated + (status === 'compliant' ? 0 : 1) });
  });
  return [...map.values()];
}

function getErrorMessage(item, errorMessage) {
  let updatedErrorMessage = errorMessage;
  if (item.code >= 400 || item.status === POLICY_FAILURE_STATUS) {
    updatedErrorMessage += `${item.message}\n`;
  }

  return updatedErrorMessage;
}

export default class ComplianceModel {
  constructor({ kubeConnector }) {
    if (!kubeConnector) {
      throw new Error('kubeConnector is a required parameter');
    }

    this.kubeConnector = kubeConnector;
  }

  async createPolicy(resources) {
    // TODO: revist this, do something like application,
    // combine policy and compliance into one mutation
    let errorMessage = '';
    const result = await Promise.all(resources.map((resource) => {
      const namespace = _.get(resource, metadataNsStr, (config.get('complianceNamespace') || 'acm'));
      return this.kubeConnector.post(`${policyAPIPrefix}/${namespace}/policies`, resource)
        .catch((err) => Error(err));
    }));
    result.forEach((item) => {
      errorMessage = getErrorMessage(item, errorMessage);
    });
    if (errorMessage) {
      throw new Error(errorMessage);
    } else {
      // TODO: add partical errors
      return result;
    }
  }

  async deletePolicy(input) {
    const response = await this.kubeConnector.delete(`${policyAPIPrefix}/${input.namespace}/policies/${input.name}`);
    if (response.code || response.message) {
      throw new Error(`ACM ERROR ${response.code} - ${response.message}`);
    }
    return response.metadata.name;
  }

  async deleteCompliance(input) {
    const response = await this.kubeConnector.delete(input.selfLink);
    if (response.code || response.message) {
      throw new Error(`GRC ERROR ${response.code} - ${response.message}`);
    }
    const errors = await this.deleteComplianceResource(input.resources);
    if (errors && errors.length > 0) {
      throw new Error(`GRC ERROR: Unable to delete application resource(s) - ${JSON.stringify(errors)}`);
    }
    return response.metadata.name;
  }

  async deleteComplianceResource(resources = []) {
    if (resources.length < 1) {
      logger.info('No Compliance resources selected for deletion');
      return [];
    }

    const result = await Promise.all(resources.map((resource) => this.kubeConnector.delete(resource.selfLink).catch((err) => ({
      status: 'Failure',
      message: err.message,
    }))));

    const errors = [];
    result.forEach((item) => {
      if (item.code >= 400 || item.status === 'Failure') {
        errors.push({ message: item.message });
      }
    });

    return errors;
  }

  // get a single policy on a specific namespace
  async getSinglePolicy(policies, name, urlNS) {
    const URL = `${policyAPIPrefix}/${urlNS}/policies/${name}`;
    const policyResponse = await this.kubeConnector.get(URL);
    if (policyResponse.code || policyResponse.message) {
      logger.debug(`GRC ERROR ${policyResponse.code} - ${policyResponse.message} - URL : ${URL}`);
    } else {
      policies.push(policyResponse);
    }
    return policies;
  }

  // get a single policy on all non-clusters namespaces
  async getSinglePolicyAllNS(name, allNonClusterNS) {
    const promises = allNonClusterNS.map(async (ns) => {
      const URL = `${policyAPIPrefix}/${ns || config.get('complianceNamespace') || 'acm'}/policies/${name}`;
      const policyResponse = await this.kubeConnector.get(URL);
      if (policyResponse.code || policyResponse.message) {
        logger.debug(`GRC ERROR ${policyResponse.code} - ${policyResponse.message} - URL : ${URL}`);
        return null;// 404 or not found
      }
      return policyResponse;// found policy
    });
    // here need to await all async calls completed then combine their results together
    const policyResponses = await Promise.all(promises);
    // remove no found policies
    return policyResponses.filter((policyResponse) => policyResponse !== null);
  }

  // get the policy list on a specific namespace
  async getPolicyListSingleNS(urlNS) {
    const URL = `${policyAPIPrefix}/${urlNS}/policies`;
    const policyResponse = await this.kubeConnector.get(URL);
    if (policyResponse.code || policyResponse.message) {
      logger.debug(`GRC ERROR ${policyResponse.code} - ${policyResponse.message} - URL : ${URL}`);
    }
    return policyResponse.items || [];
  }

  // general case for all policies, get the policy list on all non-clusters namespaces
  async getPolicyListAllNS(allNonClusterNS) {
    const promises = allNonClusterNS.map(async (ns) => {
      const URL = `${policyAPIPrefix}/${ns || config.get('complianceNamespace') || 'acm'}/policies`;
      const policyResponse = await this.kubeConnector.get(URL);
      if (policyResponse.code || policyResponse.message) {
        logger.debug(`GRC ERROR ${policyResponse.code} - ${policyResponse.message} - URL : ${URL}`);
        if (policyResponse.code === 403) {
          throw new ApolloError('PermissionError', {
            message: policyResponse.message,
          });
        }
      }
      return policyResponse.items;
    });
    // here need to await all async calls completed then combine their results together
    const policyResponses = await Promise.all(promises);
    // remove empty policies namespaces
    // flatten 'array of array of object' to 'array of object'
    const policies = _.flatten(policyResponses.filter((policyResponse) => policyResponse.length > 0));
    // filter out policies with policy.open-cluster-management.io/root-policy label
    return policies.filter((policy) => _.get(policy, ['metadata', 'labels', 'policy.open-cluster-management.io/root-policy']) === undefined);
  }

  async getCompliances(name, namespace) {
    const urlNS = namespace || (config.get('complianceNamespace') ? config.get('complianceNamespace') : 'acm');
    let policies = [];
    let clusterNS = {};
    let clusterConsoleURL = {};

    if (namespace) {
      if (name) {
        policies = await this.getSinglePolicy(policies, name, urlNS);
      } else {
        policies = await this.getPolicyListSingleNS(urlNS);
      }
    } else {
      const {
        clusterNSTemp,
        clusterConsoleURLTemp,
        allNonClusterNS,
      } = await getTypedNS(this.kubeConnector, 'allNonClusterNS');
      clusterNS = clusterNSTemp;
      clusterConsoleURL = clusterConsoleURLTemp;
      if (name) {
        policies = await this.getSinglePolicyAllNS(name, allNonClusterNS);
      } else {
        policies = await this.getPolicyListAllNS(allNonClusterNS);
      }
    }

    return policies.map((entry) => ({
      ...entry,
      raw: entry,
      name: _.get(entry, metadataNameStr, ''),
      namespace: _.get(entry, metadataNsStr, ''),
      remediation: _.get(entry, specReActionStr, ''),
      clusters: _.keys(_.get(entry, statusStatusStr), ''),
      clusterNS,
      clusterConsoleURL,
    }));
  }

  static resolveCompliancePolicies(parent) {
    const aggregatedStatus = _.get(parent, statusStatusStr);
    // compliance that has aggregatedStatus
    if (aggregatedStatus) {
      return this.resolvePolicyFromStatus(aggregatedStatus, parent);
    }
    // in this case, a compliance doesn't connect with a
    // placementPolicy may not have aggregatedStatus
    return this.resolvePolicyFromSpec(parent);
  }

  static resolveCompliancePolicy(parent) {
    const aggregatedStatus = _.get(parent, statusStatusStr);
    return this.resolveCompliancePoliciesFromSpec(parent, aggregatedStatus);
  }

  static resolveCompliancePoliciesFromSpec(parent, aggregatedStatus) {
    const compliancePolicies = {};
    const policies = _.get(parent, specRuntimeRulesStr)
      ? _.get(parent, specRuntimeRulesStr) : [parent];
    policies.forEach((policy) => {
      const key = _.get(policy, metadataNameStr);
      const value = {
        name: _.get(policy, metadataNameStr),
        complianceName: _.get(parent, metadataNameStr),
        complianceNamespace: _.get(parent, metadataNsStr),
        complianceSelfLink: _.get(parent, 'metadata.selfLink'),
        roleTemplates: this.resolvePolicyTemplates(policy, roleTemplatesStr),
        roleBindingTemplates: this.resolvePolicyTemplates(policy, roleBindingTemplatesStr),
        objectTemplates: this.resolvePolicyTemplates(policy, objectTemplatesStr),
        policyTemplates: this.resolvePolicyTemplates(policy, policyTemplatesStr),
        detail: this.resolvePolicyDetails(policy),
        raw: policy,
      };
      compliancePolicies[key] = value;
    });

    if (aggregatedStatus) {
      Object.values(aggregatedStatus).forEach((cluster) => {
        Object.entries(_.get(cluster, 'aggregatePoliciesStatus', {})).forEach(([key, value]) => {
          let policy;
          if (parent.spec[runtimeRulesStr]) {
            policy = parent.spec[runtimeRulesStr].find((p) => p.metadata.name === key);
          }
          const policyObject = {
            compliant: this.resolveStatus(value),
            remediation: _.get(policy, specReActionStr, 'unknown'),
            message: _.get(value, 'message', '-'),
            rules: this.resolvePolicyRules(policy), // TODO: Use resolver.
            status: this.resolveStatus(value),
            violations: this.resolvePolicyViolations(policy, cluster), // TODO: Use resolver.
            metadata: {
              ...parent.metadata,
              name: key,
            },
          };

          compliancePolicies[key] = { ...compliancePolicies[key], ...policyObject };
        });
      });
    }

    return Object.values(compliancePolicies);
  }

  static resolvePolicyFromStatus(aggregatedStatus, parent) {
    const compliancePolicies = [];
    Object.values(aggregatedStatus).forEach((cluster) => {
      Object.entries(_.get(cluster, 'aggregatePoliciesStatus', {})).forEach(([key, value]) => {
        let policy;
        if (parent.spec[runtimeRulesStr]) {
          policy = parent.spec[runtimeRulesStr].find((p) => p.metadata.name === key);
        }
        const policyObject = {
          cluster: _.get(cluster, 'clustername', parent.metadata.namespace),
          complianceName: parent.metadata.name,
          complianceNamespace: parent.metadata.namespace,
          compliant: this.resolveStatus(value),
          remediation: _.get(policy, specReActionStr, 'unknown'),
          message: _.get(value, 'message', '-'),
          name: key,
          rules: this.resolvePolicyRules(policy), // TODO: Use resolver.
          status: this.resolveStatus(value),
          valid: this.resolveValid(value),
          violations: this.resolvePolicyViolations(policy, cluster), // TODO: Use resolver.
          roleTemplates: this.resolvePolicyTemplates(policy, roleTemplatesStr),
          roleBindingTemplates: this.resolvePolicyTemplates(policy, roleBindingTemplatesStr),
          objectTemplates: this.resolvePolicyTemplates(policy, objectTemplatesStr),
          detail: this.resolvePolicyDetails(policy),
          raw: policy,
          metadata: {
            ...parent.metadata,
            name: key,
          },
        };

        compliancePolicies.push(policyObject);
      });
    });

    const tempResult = {};
    Object.values(compliancePolicies).forEach((policy) => {
      if (!tempResult[policy.name]) {
        tempResult[policy.name] = {
          name: _.get(policy, 'name'),
          complianceName: _.get(policy, 'complianceName'),
          complianceNamespace: _.get(policy, 'complianceNamespace'),
          clusterCompliant: [],
          clusterNotCompliant: [],
          policies: [],
        };
      }
      tempResult[policy.name].policies.push(policy);
      if (_.get(policy, 'compliant', '').toLowerCase() === 'compliant') {
        tempResult[policy.name].clusterCompliant.push(_.get(policy, 'cluster'));
      } else {
        tempResult[policy.name].clusterNotCompliant.push(_.get(policy, 'cluster'));
      }
    });
    return Object.values(tempResult);
  }

  static resolvePolicyFromSpec(parent) {
    const compliancePolicies = [];
    const policies = _.get(parent, specRuntimeRulesStr, []);
    policies.forEach((policy) => {
      compliancePolicies.push({
        name: _.get(policy, metadataNameStr),
        complianceName: _.get(parent, metadataNameStr),
        complianceNamespace: _.get(parent, metadataNsStr),
      });
    });
    return Object.values(compliancePolicies);
  }

  static resolveStatus(parent) {
    return _.get(parent, 'Compliant') || _.get(parent, 'compliant', 'unknown');
  }

  static resolveValid(parent) {
    if (_.get(parent, 'Valid') !== undefined) {
      return _.get(parent, 'Valid') ? true : 'invalid';
    }
    if (_.get(parent, 'valid') !== undefined) {
      return _.get(parent, 'valid') ? true : 'invalid';
    }
    return 'unknown';
  }

  static resolveComplianceStatus(parent) {
    const complianceStatus = [];
    Object.entries(_.get(parent, statusStatusStr, {}))
      .forEach(([clusterName, perClusterStatus]) => {
        const aggregatedStatus = _.get(perClusterStatus, 'aggregatePoliciesStatus', {});

        // get compliant status per cluster
        if (aggregatedStatus) {
          let validNum = 0;
          let compliantNum = 0;
          let policyNum = 0;
          Object.values(aggregatedStatus).forEach((object) => {
            if (this.resolveStatus(object) === 'Compliant') {
              compliantNum += 1;
            }
            if (this.resolveValid(object)) {
              validNum += 1;
            }
            policyNum += 1;
          });
          complianceStatus.push({
            clusterNamespace: clusterName,
            localCompliantStatus: `${compliantNum}/${policyNum}`,
            localValidStatus: `${validNum}/${policyNum}`,
            compliant: _.get(perClusterStatus, 'compliant', '-'),
          });
        }
      });

    return complianceStatus;
  }

  static resolvePolicyCompliant({ status = {} }) {
    let totalPolicies = 0;
    let compliantPolicies = 0;

    Object.values(status.status || []).forEach((cluster) => {
      Object.values(cluster.aggregatePoliciesStatus || {}).forEach((policyValue) => {
        totalPolicies += 1;
        if (this.resolveStatus(policyValue).toLowerCase() === 'compliant') {
          compliantPolicies += 1;
        }
      });
    });

    return `${totalPolicies - compliantPolicies}/${totalPolicies}`;
  }

  static resolveClusterCompliant({ status = {} }) {
    if (status && status.status) {
      const totalClusters = Object.keys(status.status).length;
      const noncompliantClusters = Object.values(status.status || [])
        .filter((cluster) => (_.get(cluster, 'compliant', '').toLowerCase() === 'noncompliant'));
      const compliantClusters = Object.values(status.status || [])
        .filter((cluster) => (_.get(cluster, 'compliant', '').toLowerCase() === 'compliant'));
      const pendingClusters = totalClusters - noncompliantClusters.length - compliantClusters.length;
      return `${noncompliantClusters.length}/${totalClusters}/${pendingClusters}`;
    }
    return '-';
  }

  static resolveAnnotations(parent) {
    const rawAnnotations = _.get(parent, 'metadata.annotations', {});
    return {
      categories: _.get(rawAnnotations, `${ApiGroup.policiesGroup}/categories`, '-'),
      controls: _.get(rawAnnotations, `${ApiGroup.policiesGroup}/controls`, '-'),
      standards: _.get(rawAnnotations, `${ApiGroup.policiesGroup}/standards`, '-'),
    };
  }

  async getPlacementRulesFromParent(parent = {}) {
    const placements = _.get(parent, 'status.placement', []);
    const map = new Map();
    const placementPolicies = [];
    if (parent.namespace) {
      const response = await this.kubeConnector.getResources(
        (ns) => `${appAPIPrefix}/${ns}/placementrules`,
        { kind: 'PlacementRule', namespaces: [parent.namespace] },
      );
      if (response) {
        response.forEach((item) => map.set(item.metadata.name, item));
      }
    } else {
      logger.debug('Parent policy does not contain a namespace to get placementRules from:', parent);
    }
    placements.forEach((placement) => {
      const rule = _.get(placement, 'placementRule', '');
      const pp = map.get(rule);
      if (pp) {
        const spec = pp.spec || {};
        placementPolicies.push({
          clusterLabels: spec.clusterSelector,
          metadata: pp.metadata,
          raw: pp,
          status: pp.status,
        });
      }
    });
    return placementPolicies;
  }

  async getPlacementBindingsFromParent(parent = {}) {
    const placements = _.get(parent, 'status.placement', []);
    const map = new Map();
    const placementBindings = [];
    if (parent.namespace) {
      const response = await this.kubeConnector.getResources(
        (ns) => `${policyAPIPrefix}/${ns}/placementbindings`,
        { kind: 'PlacementBinding', namespaces: [parent.namespace] },
      );
      if (response) {
        response.forEach((item) => map.set(item.metadata.name, item));
      }
    } else {
      logger.debug('Parent policy does not contain a namespace to get placementBindings from:', parent);
    }

    placements.forEach((placement) => {
      const binding = _.get(placement, 'placementBinding', '');
      const pb = map.get(binding);
      if (pb) {
        placementBindings.push({
          metadata: pb.metadata,
          raw: pb,
          placementRef: pb.placementRef,
          subjects: pb.subjects,
        });
      }
    });
    return placementBindings;
  }

  async getPlacementRules(prs = []) {
    const response = await this.kubeConnector.getResources(
      (ns) => `${appAPIPrefix}/${ns}/placementrules`,
      { kind: 'PlacementRule' },
    );
    const map = new Map();
    if (response) {
      response.forEach((item) => map.set(item.metadata.name, item));
    }
    const placementPolicies = [];

    prs.forEach((rule) => {
      const pp = map.get(rule);
      if (pp) {
        const spec = pp.spec || {};
        placementPolicies.push({
          clusterLabels: spec.clusterSelector,
          metadata: pp.metadata,
          raw: pp,
          status: pp.status,
        });
      }
    });
    return placementPolicies;
  }

  async getPlacementBindings(pbs = []) {
    const response = await this.kubeConnector.getResources(
      (ns) => `${policyAPIPrefix}/${ns}/placementbindings`,
      { kind: 'PlacementBinding' },
    );
    const map = new Map();
    if (response) {
      response.forEach((item) => map.set(item.metadata.name, item));
    }
    const placementBindings = [];

    pbs.forEach((binding) => {
      const pb = map.get(binding);
      if (pb) {
        placementBindings.push({
          metadata: pb.metadata,
          raw: pb,
          placementRef: pb.placementRef,
          subjects: pb.subjects,
        });
      }
    });
    return placementBindings;
  }

  async getPolicies(name, clusterName) {
    const policyResult = [];
    if (name !== null) {
      const URL = `${policyAPIPrefix}/${clusterName}/policies/${name}`;
      const policyResponse = await this.kubeConnector.get(URL);
      if (policyResponse.code || policyResponse.message) {
        logger.debug(`GRC ERROR ${policyResponse.code} - ${policyResponse.message} - URL : ${URL}`);
        return null;// 404 or not found
      }
      policyResult.push({
        cluster: _.get(policyResponse, 'metadata.namespace'),
        ...policyResponse,
        raw: policyResponse,
      });
    }
    return policyResult;
  }

  async getAllPoliciesInCluster(cluster) {
    const allPoliciesInClusterResult = [];
    // if cluster name specified
    if (cluster !== undefined) {
      const URL = `${policyAPIPrefix}/${cluster}/policies/`;
      const policyListResponse = await this.kubeConnector.get(URL);
      const policyListItems = _.get(policyListResponse, 'items');
      if (Array.isArray(policyListItems) && policyListItems.length > 0) {
        policyListItems.forEach((policyListItem) => {
          const policyNS = _.get(policyListItem, metadataNsStr);
          if (policyNS && policyNS.trim().toLowerCase() === cluster.trim().toLowerCase()) {
            const policiesStatusDetails = [];
            const policyListDetails = _.get(policyListItem, statusDetails);
            if (Array.isArray(policyListDetails) && policyListDetails.length > 0) {
              policyListDetails.forEach((detail) => {
                policiesStatusDetails.push({
                  name: _.get(detail, templateMetaNameStr, '-'),
                  compliant: _.get(detail, 'compliant', '-'),
                  message: _.get(detail, historyLatestMessageStr, '-'),
                  lastTimestamp: _.get(detail, historyLatestTimestampStr, '-'),
                });
              });
            }
            allPoliciesInClusterResult.push({ cluster, ...policyListItem, policiesStatusDetails });
          }
        });
      }
    }
    return allPoliciesInClusterResult;
  }

  async getAllClustersInPolicy(policyName, hubNamespace) {
    let allClustersInPolicyResult = [];
    if (policyName && hubNamespace) {
      // step 1 get the clusters associated with this policy (policyName)
      const policyDetailsURL = `${policyAPIPrefix}/${hubNamespace}/policies/${policyName}`;
      const policyDetails = await this.kubeConnector.get(policyDetailsURL);
      const clustersList = _.get(policyDetails, statusStatusStr);
      if (Array.isArray(clustersList) && clustersList.length > 0) {
        // step 2 set cluster violated info for this policy
        let temp = [];
        clustersList.forEach((cluster) => {
          if (typeof cluster.compliant === 'string') {
            if (cluster.compliant.trim().toLowerCase() === 'compliant') {
              temp.push({ name: cluster.clustername, status: 'compliant' });
            } else if (cluster.compliant.trim().toLowerCase() === 'noncompliant') {
              temp.push({ name: cluster.clustername, status: 'violated' });
            } else {
              temp.push({ name: cluster.clustername, status: 'pending' });
            }
          }
        });
        // step 3 calculate violated clusters number / total clusters number
        temp = createStatusResult(temp);
        // step 4 for each cluster from step 1, get the policies list info on that cluster
        const policyListPromise = temp.map(async (cluster) => {
          const singlePolicyListURL = `${policyAPIPrefix}/${cluster.name}/policies/`;
          const singlePolicyList = await this.kubeConnector.get(singlePolicyListURL);
          const policyListItems = _.get(singlePolicyList, 'items');
          const policyListStatuses = [];
          // only keep policies list info for this policy (policyName)
          if (Array.isArray(policyListItems) && policyListItems.length > 0) {
            policyListItems.forEach((policyListItem) => {
              const itemName = _.get(policyListItem, 'metadata.name').trim().toLowerCase();
              if (itemName === `${hubNamespace.trim().toLowerCase()}.${policyName.trim().toLowerCase()}`
              || itemName === policyName.trim().toLowerCase()) {
                const policyListDetails = _.get(policyListItem, statusDetails);
                if (Array.isArray(policyListDetails) && policyListDetails.length > 0) {
                  policyListDetails.forEach((detail) => {
                    policyListStatuses.push({
                      name: _.get(detail, templateMetaNameStr, '-'),
                      compliant: _.get(detail, 'compliant', '-'),
                      message: _.get(detail, historyLatestMessageStr, '-'),
                      lastTimestamp: _.get(detail, historyLatestTimestampStr, '-'),
                    });
                  });
                }
              }
            });
          }
          return {
            ...cluster,
            policyListStatuses,
          };
        });
        allClustersInPolicyResult = await Promise.all(policyListPromise);
        // step 5 get cluster info like consoleURL
        const [clustersInfos] = await Promise.all([
          this.kubeConnector.getResources((ns) => `${clusterAPIPrefix}/${ns}/managedclusterinfos`),
        ]);
        const clustersInfosMap = new Map();
        if (Array.isArray(clustersInfos) && clustersInfos.length > 0) {
          clustersInfos.forEach((info) => {
            clustersInfosMap.set(
              _.get(info, metadataNameStr, ''),
              { metadata: _.get(info, 'metadata'), status: { consoleURL: _.get(info, 'status.consoleURL', '') } },
            );
          });
        }
        allClustersInPolicyResult = allClustersInPolicyResult.map((clusterData) => {
          const clusterInfo = clustersInfosMap.get(clusterData.name);
          return {
            ...clusterData, ...clusterInfo,
          };
        });
      }
    }
    return allClustersInPolicyResult;
  }

  async getPolicyFromClusterNS(allClusterNS, hubNamespace, policyName) {
    const promises = allClusterNS.map(async (ns) => {
      const URL = `${policyAPIPrefix}/${ns}/policies/${hubNamespace}.${policyName}`;
      const policyResponse = await this.kubeConnector.get(URL);
      if (policyResponse.code || policyResponse.message) {
        logger.debug(`GRC ERROR ${policyResponse.code} - ${policyResponse.message} - URL : ${URL}`);
        return null;// 404 or not found
      }
      return policyResponse;// found policy
    });
    // here need to await all async calls completed then combine their results together
    const policyResponses = await Promise.all(promises);
    // remove no found policies
    policyResponses.filter((policyResponse) => {
      if (policyResponse === null || policyResponse === undefined) {
        return false;
      }
      return true;
    });
    return policyResponses;
  }

  async getStatusHistory(policyName, hubNamespace, cluster, templateName) {
    const resultsWithPolicyName = [];
    if (!(policyName && hubNamespace && cluster && templateName)) {
      return resultsWithPolicyName;
    }
    const allClusterNS = [cluster];
    const policyResponses = await this.getPolicyFromClusterNS(allClusterNS, hubNamespace, policyName);
    // Policy history are to be generated from all violated policies get above.
    // Current violation status are to be get from histroy[most-recent]
    const statuses = [];
    policyResponses.forEach((policyResponse) => {
      let details = _.get(policyResponse, statusDetails, []);
      details = details.filter((detail) => {
        if (_.get(detail, templateMetaNameStr, 'unknown') === templateName) {
          return true;
        }
        return false;
      });
      details.forEach((detail) => {
        const history = _.get(detail, 'history', []);
        history.forEach((status) => {
          statuses.push({
            message: _.get(status, 'message', '-'),
            timestamp: _.get(status, 'lastTimestamp', '-'),
          });
        });
      });
    });
    return statuses;
  }

  async getAllStatusInPolicy(policyName, hubNamespace) {
    const resultsWithPolicyName = [];
    if (!(policyName && hubNamespace)) {
      return resultsWithPolicyName;
    }
    // nsType === 'allClusterNS', get the list of all clusters namespaces
    const { allClusterNS, clusterConsoleURLTemp } = await getTypedNS(this.kubeConnector, 'allClusterNS');
    const policyResponses = await this.getPolicyFromClusterNS(allClusterNS, hubNamespace, policyName);
    // Policy history are to be generated from all compliant/non-compliant policies get above.
    // Current violation status are to be get from histroy[most-recent]
    const status = [];
    policyResponses.forEach((policyResponse) => {
      const cluster = _.get(policyResponse, 'metadata.labels["policy.open-cluster-management.io/cluster-name"]', '-');
      const clusterNamespace = _.get(policyResponse, 'metadata.labels["policy.open-cluster-management.io/cluster-namespace"]', '-');
      const details = _.get(policyResponse, statusDetails, []);
      details.forEach((detail) => {
        const templates = _.get(policyResponse, 'spec.policy-templates', []);
        const template = templates.find((t) => _.get(t, 'objectDefinition.metadata.name', 'a') === _.get(detail, templateMetaNameStr), 'b');
        status.push({
          templateName: _.get(detail, templateMetaNameStr, '-'),
          cluster,
          clusterNamespace,
          status: _.get(detail, 'compliant', 'no-status'),
          apiVersion: _.get(template, 'objectDefinition.apiVersion', '-'),
          kind: _.get(template, 'objectDefinition.kind', '-'),
          message: _.get(detail, historyLatestMessageStr, '-'),
          timestamp: _.get(detail, historyLatestTimestampStr),
          consoleURL: clusterConsoleURLTemp[cluster],
          policyName,
          policyNamespace: hubNamespace,
        });
      });
    });
    return status;
  }

  static resolvePolicyDetails(parent) {
    return {
      exclude_namespace: _.get(parent, 'spec.namespaces.exclude', ['*']),
      include_namespace: _.get(parent, 'spec.namespaces.include', ['*']),
    };
  }

  static resolvePolicyRemediation(parent) {
    return _.get(parent, specReActionStr, 'unknown');
  }

  static resolvePolicyRules(parent) {
    const rules = [];
    getTemplates(parent).forEach((res) => {
      if (res.rules) {
        Object.entries(res.rules).forEach(([key, rul]) => {
          const complianceType = _.get(rul, 'complianceType');
          if (complianceType) {
            const rule = {
              complianceType,
              apiGroups: _.get(rul, 'policyRule.apiGroups', ['-']),
              resources: _.get(rul, 'policyRule.resources', ['-']),
              verbs: _.get(rul, 'policyRule.verbs', ['-']),
              templateType: _.get(res, 'templateType', ''),
              ruleUID: `${_.get(res, metadataNameStr, '-')}-rule-${key}`,
            };
            rules.push(rule);
          }
        });
      }
    });
    return rules;
  }

  static resolveRoleSubjects(parent) {
    let roleSubjects = [];
    getTemplates(parent).forEach((res) => {
      if (_.get(res, 'templateType') === roleBindingTemplatesStr) {
        roleSubjects = [..._.get(res, 'roleBinding.subjects', [])];
      }
    });
    return roleSubjects;
  }

  static resolveRoleRef(parent) {
    const roleRef = [];
    getTemplates(parent).forEach((res) => {
      if (_.get(res, 'templateType') === roleBindingTemplatesStr) {
        roleRef.push(_.get(res, 'roleBinding.roleRef', {}));
      }
    });
    return roleRef;
  }

  static resolvePolicyStatus(parent) {
    if (_.get(parent, statusUCompliantStr) || _.get(parent, statusLCompliantStr)) {
      return _.get(parent, 'status');
    }
    if (_.get(parent, 'status.Valid') !== undefined) {
      return _.get(parent, 'status.Valid') ? 'valid' : 'invalid';
    }
    if (_.get(parent, 'status.valid') !== undefined) {
      return _.get(parent, 'status.valid') ? 'valid' : 'invalid';
    }
    return 'unknown';
  }

  static resolvePolicyMessage(parent) {
    return _.get(parent, 'status.message', '-');
  }

  static resolvePolicyTemplates(parent, type) {
    const vioArray = this.resolvePolicyViolations(parent, true);
    const tempArray = [];
    getTemplates(parent).forEach((res) => {
      if (_.get(res, 'templateType') === type) {
        if (type === roleBindingTemplatesStr) {
          const name = _.get(res, 'roleBinding.metadata.name', '-');
          tempArray.push({
            name,
            lastTransition: _.get(res, statusLastTransTimeStr, ''),
            complianceType: _.get(res, 'complianceType', ''),
            apiVersion: _.get(res, 'roleBinding.apiVersion', ''),
            compliant: _.isEmpty(vioArray.filter((vio) => _.get(vio, 'name', '') === name)) ? 'Compliant' : 'NonCompliant',
            validity: _.get(res, statusValidityValidStr) || _.get(res, statusValidityStr, ''),
            raw: res,
          });
        } else if (type === objectTemplatesStr || type === policyTemplatesStr) {
          const name = _.get(res, objMetadataNameStr, '-');
          tempArray.push({
            name,
            lastTransition: _.get(res, statusLastTransTimeStr, ''),
            complianceType: _.get(res, 'complianceType', ''),
            apiVersion: _.get(res, 'objectDefinition.apiVersion', ''),
            kind: _.get(res, 'objectDefinition.kind', ''),
            compliant: _.isEmpty(vioArray.filter((vio) => _.get(vio, 'name', '') === name)) ? 'Compliant' : 'NonCompliant',
            status: _.isEmpty(vioArray.filter((vio) => _.get(vio, 'name', '') === name)) ? 'Compliant' : 'NonCompliant',
            validity: _.get(res, statusValidityValidStr) || _.get(res, statusValidityStr, ''),
            raw: res,
          });
        } else {
          const name = _.get(res, metadataNameStr, '-');
          tempArray.push({
            name,
            lastTransition: _.get(res, statusLastTransTimeStr, ''),
            complianceType: _.get(res, 'complianceType', ''),
            apiVersion: _.get(res, 'apiVersion', ''),
            compliant: _.isEmpty(vioArray.filter((vio) => _.get(vio, 'name', '') === name)) ? 'Compliant' : 'NonCompliant',
            status: _.isEmpty(vioArray.filter((vio) => _.get(vio, 'name', '') === name)) ? 'Compliant' : 'NonCompliant',
            validity: _.get(res, statusValidityValidStr) || _.get(res, statusValidityStr, ''),
            raw: res,
          });
        }
      }
    });
    return tempArray;
  }

  static resolvePolicyViolations(parent, displayVioOnly = false) {
    const violationArray = [];
    let details = _.get(parent, statusDetails, []);
    if (displayVioOnly) {
      details = details.filter((detail) => _.get(detail, 'compliant', 'unknown') !== 'Compliant');
    }
    const cluster = _.get(parent, 'cluster', '-');
    details.forEach((detail) => {
      violationArray.push({
        name: _.get(detail, templateMetaNameStr, '-'),
        cluster,
        message: _.get(detail, historyLatestMessageStr, '-'),
        timestamp: _.get(detail, historyLatestTimestampStr),
      });
    });
    return violationArray;
  }
}
