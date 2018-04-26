'use strict';

import {FlowNode} from "./FlowNode.js";
import {FreeNodePortLocationModel} from "../../../lib/yfiles/view-component.js";

export class FlowReturn extends FlowNode {

    constructor(node) {
        super(node);
    }

    render(graph) {
        let labelText = "";
        labelText += `<p><b>${this.dbNode.query}</b></p>`;
        labelText += `<p>${this.dbNode.type}</p>`;

        let node = super.render(graph,labelText)

        this.ports['dataSource'] = graph.addPort(node, FreeNodePortLocationModel.NODE_TOP_ANCHORED);
        this.ports['prev'] = graph.addPort(node, FreeNodePortLocationModel.NODE_LEFT_ANCHORED);
        this.ports['next'] = graph.addPort(node, FreeNodePortLocationModel.NODE_RIGHT_ANCHORED);
        this.ports['dataTarget'] = graph.addPort(node, FreeNodePortLocationModel.NODE_BOTTOM_ANCHORED);
    }

}