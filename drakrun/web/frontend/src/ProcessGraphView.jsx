import { useEffect, useState, useCallback } from "react";
import { getAnalysisProcessGraph } from "./api.js";
import { ProcessGraph } from "./ProcessGraph.jsx";


export function ProcessGraphView({
    analysisId,
    onElementSelect,
}) {
    const [graphElements, setGraphElements] = useState(null);
    const [selectedElementData, setSelectedElementData] = useState(null);
    const [loading, setLoading] = useState();
    const [error, setError] = useState();

    const fetchGraphData = useCallback((AbortController) => {
        setLoading(true);
        setError(null);
        getAnalysisProcessGraph( {analysisId, AbortController })
            .then((data) => {

                const nodesWithoutId = data.elements.nodes.filter(n => !n.data.id);
                const edgesWithoutId = data.elements.edges.filter(e => !e.data.id);

                if (nodesWithoutId.length > 0) {
                    console.error("ERROR: The following nodes are missing an ID:", nodesWithoutId);
                }
                if (edgesWithoutId.length > 0) {
                    console.error("ERROR: The following edges are missing an ID:", edgesWithoutId);
                }

                setGraphElements(data.elements);
            })
            .catch((e) => {
                console.error(e);
                setError(e);
            })
            .finally(() => {
                setLoading(false);
            });

    }, [analysisId]);

    useEffect(() => {
        const abortController = new AbortController();
        fetchGraphData(abortController);
        return () => abortController.abort();
    }, [fetchGraphData]);

    /*
    const handleElementSelect = (element) => {
        if (onElementSelect) {
            onElementSelect(element);
        }
        setSelectedElementData(element); 
    };
    */

    const handleElementSelect = useCallback((element) => {
        if (onElementSelect) {
            onElementSelect(element);
        }
        setSelectedElementData(element); 
    }, [onElementSelect]);

    return (
    <div className="position-relative">
        <ProcessGraph elements={graphElements} onElementSelect={handleElementSelect} />
        
        {loading && <div className="overlay">Loading...</div>}
        {error && <div className="overlay">Error: {error}</div>}
        {!graphElements && <div className="overlay">No data</div>}
    </div>
);
}
 