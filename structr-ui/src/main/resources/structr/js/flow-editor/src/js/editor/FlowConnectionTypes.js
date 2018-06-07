'use strict';

export class FlowConnectionTypes {

    constructor() {
        this._connectionTypes = {
            FlowDataInput: {
                name: "DATA",
                sourceAttribute: "dataTarget",
                targetAttribute: "dataSource",
                type: "FlowDataInput"
            },
            FlowNodes: {
                name: "NEXT_FLOW_NODE",
                sourceAttribute: "next",
                targetAttribute: "prev",
                type: "FlowNodes"
            },
            FlowCallParameter: {
                name: "INPUT_FOR",
                sourceAttribute: "call",
                targetAttribute: "parameters",
                type: "FlowCallParameter"
            },
            FlowConditionDataInput: {
                name: "DATA_INPUT",
                sourceAttribute: "dataTarget",
                targetAttribute: "dataSources",
                type: "FlowConditionDataInput"
            },
            FlowDecisionCondition: {
                name: "CONDITION",
                sourceAttribute: "result",
                targetAttribute: "condition",
                type: "FlowDecisionCondition"
            },
            FlowConditionCondition: {
                name: "CONDITION",
                sourceAttribute: "result",
                targetAttribute: "conditions",
                type: "FlowConditionCondition"
            },
            FlowDecisionTrue: {
                name: "TRUE_RESULT",
                sourceAttribute: "trueElement",
                targetAttribute: "prev",
                type: "FlowDecisionTrue"
            },
            FlowDecisionFalse: {
                name: "FALSE_RESULT",
                sourceAttribute: "falseElement",
                targetAttribute: "prev",
                type: "FlowDecisionFalse"
            },
            FlowKeyValueObjectInput: {
                name: "KEY_VALUE_SOURCE",
                sourceAttribute: "objectDataTarget",
                targetAttribute: "keyValueSources",
                type: "FlowKeyValueObjectInput"
            },
            FlowForEachBody: {
                name: "LOOP_BODY",
                sourceAttribute: "loopBody",
                targetAttribute: "prev",
                type: "FlowForEachBody"
            },
            FlowAggregateStartValue: {
                name: "START_VALUE",
                sourceAttribute: "dataTarget",
                targetAttribute: "startValue",
                type: "FlowAggregateStartValue"
            },
            FlowScriptConditionSource: {
                name: "SCRIPT_SOURCE",
                sourceAttribute: "dataTarget",
                targetAttribute: "scriptSource",
                type: "FlowScriptConditionSource"
            },
            FlowNodeDataSource: {
                name: "NODE_SOURCE",
                sourceAttribute: "dataTarget",
                targetAttribute: "nodeSource",
                type: "FlowNodeDataSource"
            },
            FlowNameDataSource: {
                name: "NAME_SOURCE",
                sourceAttribute: "dataTarget",
                targetAttribute: "propertyNameSource",
                type: "FlowNameDataSource"
            }

        };


    }

    static getInst() {
        if (window._flowConnectionTypesInst === undefined) {
            window._flowConnectionTypesInst = new FlowConnectionTypes();
        }
        return _flowConnectionTypesInst;
    }

    getAllConnectionTypes() {
        return this._connectionTypes;
    }

    getConnectionType(key) {
        return this._connectionTypes[key];
    }

}