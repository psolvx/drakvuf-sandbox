import React from 'react';

function EventDetails({ event }) {
    if (!event) return null;
    return (
        <div className="card mb-2 bg-light border-light">
            <div className="card-body p-2">
                <h6 className="card-title small mb-1">{event.method} (Event ID: {event.evtid})</h6>
                <pre className="p-2" style={{ maxHeight: '400px', overflowY: 'auto', fontSize: '0.75rem', backgroundColor: '#f8f9fa' }}>
                    {JSON.stringify(event.raw_entries, null, 2)}
                </pre>
            </div>
        </div>
    );
}

function FindingDetails({ finding }) {
    return (
        <div className="mb-4 p-3 border rounded">
            <h5>{finding.pattern}</h5>
            <h6>Correlated Events:</h6>
            {finding.correlated_events.map(event => (
                <EventDetails key={event.evtid} event={event} />
            ))}
        </div>
    );
}


export function DetectionInfoView({ selectedElement }) {
    if (!selectedElement) {
        return <div className="p-3 text-muted">Click on a node or edge to see details.</div>;
    }

    // Determine the type of element and get its data
    const isNode = selectedElement.pid !== undefined;
    const isDetectionEdge = selectedElement.type === 'detection';

    let findings = [];
    if (isNode) {
        findings = selectedElement.findings || [];
    } else if (isDetectionEdge) {
        findings = selectedElement.data?.findings || [];
    }


    return (
        <div>
            {/* Display Static Info (Process or Edge Details) */}
            {isNode && (
                <>
                    <h3>Process Details</h3>
                    <p className="mb-1"><strong>Image:</strong> {selectedElement.label.split('\n')[0]}</p>
                    <p className="mb-1"><strong>PID:</strong> {selectedElement.pid}</p>
                    <p><strong>Command Line:</strong> <code>{selectedElement.cmdline || 'N/A'}</code></p>
                </>
            )}
            {isDetectionEdge && (
                <>
                    <h3>Detection Edge Details</h3>
                    <p><strong>Pattern:</strong> {selectedElement.label}</p>
                    <p>This edge represents {findings.length} instance(s) of the detected behavior.</p>
                </>
            )}
            {!isNode && !isDetectionEdge && (
                <>
                    <h3>Element Details</h3>
                    <p>This is a structural element (e.g., a child process edge).</p>
                </>
            )}

            <hr />

            {/*Display Findings*/}
             <h4>Detections</h4>
            {findings.length > 0 ? (
                findings.map((finding, index) => (
                    <div key={index}>
                        {findings.length > 1 && <h6>Instance #{index + 1}</h6>}
                        <FindingDetails finding={finding} />
                    </div>
                ))
            ) : (
                <div className="text-muted">No specific detections found on this element.</div>
            )}
        </div>
    );
}