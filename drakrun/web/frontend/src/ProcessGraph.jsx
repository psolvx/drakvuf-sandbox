import Cytoscape from 'cytoscape';
import React, { useEffect, useRef, useState, useCallback } from 'react';
import dagre from 'cytoscape-dagre';

Cytoscape.use(dagre);

function ProcessGraphComponent({ elements, onElementSelect }) {
    const cyContainer = useRef(null);
    const cyRef = useRef(null);
    const [collapsedNodes, setCollapsedNodes] = useState(new Set());

    // Initialization
    useEffect(() => {
        if (!cyContainer.current) return;

        const cy = Cytoscape({
            container: cyContainer.current,
            style: [
                { selector: 'node', style: {
                    'background-color': '#f0f0f0', 'border-color': '#888',
                    'border-width': 2, 'label': 'data(label)',
                    'text-wrap': 'wrap', 'text-valign': 'center', 'text-halign': 'center',
                    'font-size': '10px', 'color': '#000', 'width': '90px', 'height': '40px',
                    'shape': 'round-rectangle'
                }},
                { selector: 'node[has_finding]', style: {
                    'background-color': '#f48326', 'border-color': '#888',
                    'border-width': 2, 'label': 'data(label)',
                    'text-wrap': 'wrap', 'text-valign': 'center', 'text-halign': 'center',
                    'font-size': '10px', 'color': '#000', 'width': '90px', 'height': '40px',
                    'shape': 'round-rectangle'
                }},
                { selector: 'edge[type="child"]', style: {
                    'width': 2, 'line-color': '#ccc', 'target-arrow-color': '#ccc',
                    'target-arrow-shape': 'triangle', 'curve-style': 'bezier'
                }},
                { selector: 'edge[type="detection"]', style: {
                    'width': 3, 'line-color': '#dc3545', 'target-arrow-color': '#dc3545',
                    'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'line-style': 'dashed',
                    'label': 'data(label)', 'font-size': '9px'
                }},
                { selector: ':selected', style: {
                    'border-color': '#007bff', 'border-width': 4,
                    'line-color': '#007bff', 'target-arrow-color': '#007bff'
                }}
            ],
        });
        cyRef.current = cy;

        // Event handlers
        cy.on('tap', 'node, edge', (event) => onElementSelect(event.target.data()));

        cy.on('cxttap', 'node[?child_count]', (event) => {
            const nodeId = event.target.id();
            setCollapsedNodes(current => {
                const newSet = new Set(current);
                if (newSet.has(nodeId)) newSet.delete(nodeId);
                else newSet.add(nodeId);
                return newSet;
            });
        });

        return () => {
            if (cyRef.current) {
                cyRef.current.destroy();
                cyRef.current = null;
            }
        };
    }, [onElementSelect]); 

    const getTrueDescendants = (node) => {
        return node.successors('edge[type="child"], node').nodes();
    };
    
    // Loading initial state
    useEffect(() => {
        const cy = cyRef.current;
        if (!cy || !elements) return;

        cy.json({ elements });

        const getAncestorsViaChildEdges = (node, cyInstance) => {
            const ancestors = new Set();
            let current = node;
            while (current) {
                const parentEdge = current.incomers('edge[type="child"]');
                if (parentEdge.length === 0) {
                    break; 
                }
                const parentNode = parentEdge.source();
                if (parentNode.empty() || ancestors.has(parentNode.id())) {
                    break;
                }
                ancestors.add(parentNode.id());
                current = parentNode;
            }
            return ancestors;
        };

        const importantNodes = new Set();
        
        // Nodes directly involved in findings are important
        cy.edges('[type="detection"]').forEach(edge => {
            importantNodes.add(edge.source().id());
            importantNodes.add(edge.target().id());
        });
        cy.nodes('[?findings]').forEach(node => {
            importantNodes.add(node.id());
        });
        
        // Nodes created after analysis start are important
        //cy.nodes('[?ts_from]').forEach(node => {
        //    importantNodes.add(node.id());
        //});

        // Explorer.exe is important
        const explorerNode = cy.nodes().filter(n => n.data('label')?.startsWith('explorer.exe'))[0];
        if (explorerNode) {
            importantNodes.add(explorerNode.id());
        }


        // The successors and ancestors of these nodes are also important
        const nodesToTrace = [...importantNodes]; 
        for (const nodeId of nodesToTrace) {
            const node = cy.getElementById(nodeId);
            if (!node.empty()) {
                const ancestors = getAncestorsViaChildEdges(node, cy);
                const successors = getTrueDescendants(node);
                ancestors.forEach(id => importantNodes.add(id));
                successors.forEach(node => importantNodes.add(node.id()));
            }
        }

        // remove all nodes that are not in important set.
        const nodesToRemove = cy.nodes().filter(node => !importantNodes.has(node.id()));

        if (nodesToRemove.length > 0) {
            console.log(`Removing ${nodesToRemove.length} unimportant nodes from the graph.`);
            nodesToRemove.remove();
        }
        
        // Determine which nodes to collapse initially
        /*const initialCollapsed = new Set();
        cy.nodes('[?child_count]').forEach(node => {
            if (node.data('child_count') > 0 && !importantNodes.has(node.id())) {
                initialCollapsed.add(node.id());
            }
        });
    
        setCollapsedNodes(initialCollapsed);*/
        
        cy.layout({ name: 'dagre', rankDir: 'TB', fit: true, padding: 20, animate: 'end' }).run();
    }, [elements]);




 useEffect(() => {
        const cy = cyRef.current;
        if (!cy || !cy.elements().length) return;

        cy.batch(() => {
            const allNodesToHide = cy.collection();
            
            collapsedNodes.forEach(nodeId => {
                const parentNode = cy.getElementById(nodeId);
                if (!parentNode.empty()) {
                    allNodesToHide.merge(getTrueDescendants(parentNode));
                }
            });

            const allElements = cy.elements();
            const elementsToShow = allElements.difference(allNodesToHide.union(allNodesToHide.connectedEdges()));
            const elementsToHide = allNodesToHide.union(allNodesToHide.connectedEdges());

            elementsToShow.style('display', 'element');
            elementsToHide.style('display', 'none');

            cy.nodes('[?child_count]').forEach(node => {
                const isCollapsed = collapsedNodes.has(node.id());
                node.toggleClass('collapsed-parent', isCollapsed);

                const originalLabel = (node.data('original_label') || node.data('label')).split('\n')[0];
                if (!node.data('original_label')) {
                    node.data('original_label', node.data('label'));
                }

                if (isCollapsed) {
                    const descendantCount = getTrueDescendants(node).length;
                    node.data('label', `${originalLabel}\n(+${descendantCount} hidden)`);
                } else {
                    node.data('label', originalLabel);
                }
            });
            cy.layout({ name: 'dagre', rankDir: 'TB', fit: true, padding: 20, animate: 'end' }).run();
        });
    }, [collapsedNodes]);

    return <div ref={cyContainer} style={{ height: '80vh', width: '100%' }} />;
}

export const ProcessGraph = React.memo(ProcessGraphComponent);
