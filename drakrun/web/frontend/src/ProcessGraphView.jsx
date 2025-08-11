import { useEffect, useState, useCallback } from "react";
import { getAnalysisProcessGraph } from "./api.js";
import { ProcessGraph } from "./ProcessGraph.jsx";


export function ProcessGraphView({
    analysisId,
    onProcessSelect,
}) {
    const [graphData, setGraphData] = useState(null);
    const [loading, setLoading] = useState();
    const [error, setError] = useState();

    const fetchGraphData = useCallback((AbortController) => {
        setLoading(true);
        setError(null);
        getAnalysisProcessGraph( {analysisId, AbortController })
            .then((data) => {
                setGraphData(data);
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

    if (loading) return <div>Loading...</div>;
    if (error) return <div>Error: {error}</div>;
    if (!graphData) return <div>No data</div>;

    return <ProcessGraph elements={graphData.elements} onProcessSelect={onProcessSelect}/>;
}
 