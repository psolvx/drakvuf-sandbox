import { useEffect, useState, useCallback } from "react";
import { getAnalysisProcessGraph } from "./api.js";
import { ProcessGraph } from "./ProcessGraph.jsx";


export function ProcessGraphView({
    analysisId,
    onProcessSelect,
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

    const handleElementSelect = (element) => {
        if (element) {
            setSelectedElementData(element.data());
        } else {
            setSelectedElementData(null);
        }
    };

    if (loading) return <div>Loading...</div>;
    if (error) return <div>Error: {error}</div>;
    if (!graphElements) return <div>No data</div>;

    return (
    <div className="container-fluid">
        <div className="row">
            <div className="col-12">
                <ProcessGraph elements={graphElements} onElementSelect={handleElementSelect}/>
            </div>
        </div>
    </div>
    );
}
 