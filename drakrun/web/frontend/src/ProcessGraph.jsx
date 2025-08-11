import Cytoscape from 'cytoscape';
import { useEffect, useRef } from 'react';

let BASE_URL = "";
if (import.meta.env.VITE_API_SERVER) {
    BASE_URL = import.meta.env.VITE_API_SERVER;
} else {
    BASE_URL = "/api";
}

export function ProcessGraph({ elements, onProcessSelect }) {
    const cyContainer = useRef(null);

    useEffect(() => {
        if (!cyContainer.current || !elements) return;

        const cy = Cytoscape({
            container: cyContainer.current,
            elements: elements,
            directed: true,
            multigraph: true,
            layout: {
            name: 'breadthfirst',
            },
            style: {
                'label': 'data(id)'
            }
        });


        const handleTap = (event) => {
            const node = event.target;
            if (node.isNode() && node.data('type') === 'Process'){
                onProcessSelect(node.data('seqid'));
            }
        };

        cy.on('tap', 'node', handleTap);

        return () => {
            cy.removeAllListeners();
            cy.destroy();
        };

    }, [elements, onProcessSelect]);
    
    return (
        <div className="container-fluid">
            <div className="row">
                <div ref={cyContainer} style={{ height: '70vh', width: '100%'}}></div>
            </div>
        </div>
    );
}
