import Cytoscape from 'cytoscape';
import { useEffect, useRef } from 'react';
import dagre from 'cytoscape-dagre';

let BASE_URL = "";
if (import.meta.env.VITE_API_SERVER) {
    BASE_URL = import.meta.env.VITE_API_SERVER;
} else {
    BASE_URL = "/api";
}

Cytoscape.use(dagre);

export function ProcessGraph({ elements, onElementSelect }) {
    const cyContainer = useRef(null);

    useEffect(() => {
        if (!cyContainer.current || !elements) return;

        const cy = Cytoscape({
            container: cyContainer.current,
            elements: elements,
            directed: true,
            multigraph: true,
            style: [
                // Style for all nodes
                { selector: 'node', style: {
                    'background-color': '#f0f0f0', 'border-color': '#888',
                    'border-width': 2, 'label': 'data(label)',
                    'text-wrap': 'wrap', 'text-valign': 'center', 'text-halign': 'center',
                    'font-size': '10px', 'color': '#000', 'width': '90px', 'height': '40px',
                    'shape': 'round-rectangle'
                }},
                // Style for SPAWNED edges
                { selector: 'edge[type="SPAWNED"]', style: {
                    'width': 2, 'line-color': '#ccc', 'target-arrow-color': '#ccc',
                    'target-arrow-shape': 'triangle', 'curve-style': 'bezier'
                }},
                // Style for INTERACTION_SUMMARY edges
                { selector: 'edge[type="INTERACTION_SUMMARY"]', style: {
                    'width': 3, 'line-color': '#dc3545', 'target-arrow-color': '#dc3545',
                    'target-arrow-shape': 'triangle', 'curve-style': 'bezier', 'line-style': 'dashed',
                    'label': 'data(label)', 'font-size': '9px'
                }},
                // Style for any selected element
                { selector: ':selected', style: {
                    'border-color': '#007bff', 'border-width': 4,
                    'line-color': '#007bff', 'target-arrow-color': '#007bff'
                }}
            ],
            layout: { name: 'dagre', rankDir: 'TB', spacingFactor: 1.3, fit: true, padding: 20 }
        });


        const handleTap = (event) => {
            cy.elements().unselect();
            event.target.select();
            onElementSelect(event.target);
        };

        cy.on('tap', 'node, edge', handleTap);

        return () => {
            cy.removeAllListeners();
            cy.destroy();
        };

    }, [elements, onElementSelect]);
    
    return (
        <div className="container-fluid">
            <div className="row">
                <div ref={cyContainer} style={{ height: '70vh', width: '100%'}}></div>
            </div>
        </div>
    );
}
