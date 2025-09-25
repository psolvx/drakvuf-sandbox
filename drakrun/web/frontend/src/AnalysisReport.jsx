import { useCallback, useEffect, useState } from "react";
import {
    getAnalysisSummary,
    getLog,
    getLogList,
    getProcessInfo,
    getProcessLog,
} from "./api.js";
import { TabSwitcher, Tab, useTabContext } from "./TabSwitcher.jsx";
import { getLogLoader, LogViewer } from "./LogViewer.jsx";
import { AnalysisMetadataTable } from "./AnalysisMetadataTable.jsx";
import { AnalysisScreenshotViewer } from "./AnalysisScreenshotViewer.jsx";
import { ProcessTreeView } from "./ProcessTreeView.jsx";
import { ProcessGraphView } from "./ProcessGraphView.jsx";
import { MethodFilterPicker } from "./MethodFilterPicker.jsx";
import { ProcessInfoTable } from "./ProcessInfoTable.jsx";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faDownload } from "@fortawesome/free-solid-svg-icons";
import axios, { CanceledError } from "axios";
import { AnalysisSummary } from "./AnalysisSummary.jsx";
import { ProcessBadge } from "./ProcessBadge.jsx";
import { DetectionInfoView } from "./DetectionInfoView.jsx";


export function AnalysisLogViewerTab({ analysisId }) {
    const logType = useTabContext()?.activeTab;
    const logLoaderFactory = useCallback(() => {
        return getLogLoader({
            getLogEntries: ({ rangeStart, rangeEnd }) =>
                getLog({ analysisId, logType, rangeStart, rangeEnd }),
        });
    }, [analysisId, logType]);
    if (!logType) return [];
    return <LogViewer logLoaderFactory={logLoaderFactory} />;
}

function AnalysisLogViewer({ analysisId }) {
    const [tabs, setTabs] = useState();
    const [activeTab, setActiveTab] = useState();
    const [error, setError] = useState();
    const loadLogTypes = useCallback(async () => {
        try {
            const logTypes = await getLogList({ analysisId });
            const tabs = logTypes
                .filter((logType) => logType.endsWith(".log"))
                .map((logType) => logType.split(".")[0]);
            setTabs(tabs);
            setActiveTab(tabs[0]);
        } catch (err) {
            setError(err);
            console.error(err);
        }
    }, [analysisId]);

    useEffect(() => {
        loadLogTypes();
    }, [analysisId]);

    if (typeof tabs === "undefined") {
        return <div className="py-2">Loading log information...</div>;
    }

    if (typeof error !== "undefined") {
        return (
            <div className="text-danger py-2">Error: {error.toString()}</div>
        );
    }

    return (
        <div>
            <div className="fw-bold py-2">Log type:</div>
            <div className="d-flex align-items-start">
                <TabSwitcher
                    tabs={tabs}
                    activeTab={activeTab}
                    onTabSwitch={setActiveTab}
                    tabClassName="flex-column nav-pills me-3"
                    contentClassName="flex-grow-1"
                >
                    <AnalysisLogViewerTab analysisId={analysisId} />
                </TabSwitcher>
            </div>
        </div>
    );
}

function ProcessInfoTab({ analysisId, selectedProcess, processInfo }) {
    const activeTab = useTabContext()?.activeTab;
    if (activeTab !== "Process information") {
        return [];
    }
    return <ProcessInfoTable processInfo={processInfo["process"]} />;
}

function ProcessLogViewerTab({ analysisId, selectedProcess, processInfo }) {
    const [methodsFilter, setMethodsFilter] = useState([]);
    const activeTab = useTabContext()?.activeTab;
    const logType =
        activeTab === "Process information" || !processInfo["logs"][activeTab]
            ? undefined
            : activeTab;
    const logMethods = logType ? processInfo["logs"][logType] : [];
    const logLoaderFactory = useCallback(() => {
        return getLogLoader({
            getLogEntries: ({ rangeStart, rangeEnd }) => {
                return getProcessLog({
                    analysisId,
                    logType,
                    selectedProcess,
                    rangeStart,
                    rangeEnd,
                    methodsFilter,
                });
            },
        });
    }, [analysisId, logType, selectedProcess, methodsFilter]);
    useEffect(() => {
        setMethodsFilter([]);
    }, [logType]);
    if (!logType) return [];
    return (
        <>
            <div>
                <label className="form-label">Method filter</label>
                <MethodFilterPicker
                    onFilterChange={setMethodsFilter}
                    currentFilter={methodsFilter}
                    methods={logMethods}
                />
            </div>
            <LogViewer logLoaderFactory={logLoaderFactory} />
        </>
    );
}

function ProcessLogViewer({ analysisId, selectedProcess }) {
    const [tabs, setTabs] = useState();
    const [activeTab, setActiveTab] = useState();
    const [processInfo, setProcessInfo] = useState();
    const [error, setError] = useState();
    const loadProcessInfo = useCallback(
        async (processSeqId) => {
            try {
                const processInfo = await getProcessInfo({
                    analysisId,
                    processSeqId,
                });
                const tabs = Object.keys(processInfo["logs"]);
                setProcessInfo(processInfo);
                setTabs(["Process information", ...tabs]);
                setActiveTab("Process information");
            } catch (err) {
                setError(err);
                console.error(err);
            }
        },
        [analysisId],
    );

    useEffect(() => {
        if (typeof selectedProcess === "undefined") return;
        loadProcessInfo(selectedProcess);
    }, [analysisId, selectedProcess]);

    if (typeof selectedProcess === "undefined") {
        return (
            <div className="fw-bold py-2">
                Select a process from the process tree above
            </div>
        );
    }

    if (typeof tabs === "undefined") {
        return <div className="py-2">Loading log information...</div>;
    }

    if (typeof error !== "undefined") {
        return (
            <div className="text-danger py-2">Error: {error.toString()}</div>
        );
    }

    return (
        <div>
            <div className="fw-bold py-2">Log type:</div>
            <div className="d-flex align-items-start">
                <TabSwitcher
                    tabs={tabs}
                    activeTab={activeTab}
                    onTabSwitch={setActiveTab}
                    tabClassName="flex-column nav-pills me-3"
                    contentClassName="flex-grow-1"
                >
                    <ProcessInfoTab
                        analysisId={analysisId}
                        selectedProcess={selectedProcess}
                        processInfo={processInfo}
                    />
                    <ProcessLogViewerTab
                        analysisId={analysisId}
                        selectedProcess={selectedProcess}
                        processInfo={processInfo}
                    />
                </TabSwitcher>
            </div>
        </div>
    );
}

function PaddedTab({ tab, children }) {
    return (
        <Tab tab={tab}>
            <div className="mt-2">{children}</div>
        </Tab>
    );
}

function AnalysisReportTabs({
    analysis,
    analysisSummary,
    selectedElement,
    activeTab,
    onTabSwitch,
    onSelectProcess
}) {
    const TABS = ["Summary", "Process Info", "Detection Info", "General Logs"];
    if (analysis.screenshots) {
        TABS.push("Screenshots");
    }

    const getHeader = useCallback((tab) => {
    return tab;
});

    const selectedProcess = selectedElement?.type === 'Process' ? selectedElement : null;
    const selectedDetection = selectedElement?.type === 'detection' ? selectedElement : null;

       return (
        <div className="card">
            <div className="card-body">
                <TabSwitcher
                    tabs={TABS}
                    activeTab={activeTab}
                    onTabSwitch={onTabSwitch}
                    getHeader={getHeader}
                >
                    <PaddedTab tab="Summary">
                        <AnalysisSummary
                            analysisSummary={analysisSummary}
                            setSelectedProcess={onSelectProcess}
                        />
                    </PaddedTab>

                    <PaddedTab tab="Process Info">
                        {selectedProcess ? (
                            <ProcessLogViewer
                                analysisId={analysis.id}
                                selectedProcess={selectedProcess.seqid}
                            />
                        ) : (
                            <div className="text-muted p-4 text-center">
                                <p className="mb-0">Please select a process node in the graph or tree to view its details.</p>
                            </div>
                        )}
                    </PaddedTab>

                    <PaddedTab tab="Detection Info">
                        {selectedElement ? (
                            <DetectionInfoView selectedElement={selectedElement} />
                        ) : (
                            <div className="text-muted p-4 text-center">
                                <p className="mb-0">Please select a red detection edge in the graph to view its details.</p>
                            </div>
                        )}
                    </PaddedTab>

                    <PaddedTab tab="General Logs">
                        <AnalysisLogViewer analysisId={analysis.id} />
                    </PaddedTab>
                    
                    {analysis.screenshots && (
                        <PaddedTab tab="Screenshots">
                            <AnalysisScreenshotViewer analysis={analysis} />
                        </PaddedTab>
                    )}
                </TabSwitcher>
            </div>
        </div>
    );
}



export function AnalysisReport({ analysis }) {
    const [selectedElement, setSelectedElement] = useState(null);
    const [activeTab, setActiveTab] = useState("Summary");
    const [analysisSummary, setAnalysisSummary] = useState();

    const plugins = analysis.options?.plugins;
    const baseUrl = axios.defaults.baseURL;
    const analysisId = analysis.id;

    const fetchSummary = useCallback(() => {
        getAnalysisSummary({ analysisId })
            .then((response) => {
                setAnalysisSummary(response);
            })
            .catch((error) => {
                if (!(error instanceof CanceledError)) {
                    setAnalysisSummary(null);
                    console.error(error);
                }
            });
    }, [analysisId]);

    useEffect(() => {
        fetchSummary();
    }, [analysisId, fetchSummary]);

      const handleSelectElement = useCallback((element) => {
        setSelectedElement(element);

        if (element?.type === 'Process') {
            setActiveTab("Process Info");
        } else if (element?.type === 'detection') {
            setActiveTab("Detection Info");
        }
    }, [setSelectedElement, setActiveTab]);

    const handleSelectProcessById = useCallback((seqId) => {
        if (seqId === null || seqId === undefined) {
            setSelectedElement(null);
        } else {
            const processNodeData = analysisSummary?.processes[seqId];
            handleSelectElement({
                type: 'Process',
                data: { seqid: seqId, data: processNodeData }
            });
        }
    }, [handleSelectElement, analysisSummary]);

    const selectedProcessSeqId = selectedElement?.type === 'Process' ? selectedElement.seqid : undefined;


    return (
        <>
            <div className="row">
                <div className="col-6">
                    <ProcessTreeView
                        analysisId={analysis.id}
                        selectedProcess={selectedProcessSeqId}
                        onProcessSelect={handleSelectProcessById}
                    />
                </div>
                <div className="col-6">
                    <AnalysisMetadataTable analysis={analysis} />
                    <div className="card">
                        <div className="card-body">
                            <a href={`${baseUrl}/pcap_file/${analysis.id}`}>
                                <button className="btn btn-primary m-1">
                                    <FontAwesomeIcon
                                        icon={faDownload}
                                        className="me-2"
                                    />
                                    Download PCAP
                                </button>
                            </a>
                            {Array.isArray(plugins) &&
                            plugins.includes("tlsmon") ? (
                                <a href={`${baseUrl}/pcap_keys/${analysis.id}`}>
                                    <button className="btn btn-primary m-1">
                                        <FontAwesomeIcon
                                            icon={faDownload}
                                            className="me-2"
                                        />
                                        TLS keys
                                    </button>
                                </a>
                            ) : (
                                []
                            )}
                            {Array.isArray(plugins) &&
                            plugins.includes("memdump") ? (
                                <a href={`${baseUrl}/dumps/${analysis.id}`}>
                                    <button className="btn btn-primary m-1">
                                        <FontAwesomeIcon
                                            icon={faDownload}
                                            className="me-2"
                                        />
                                        Memory dumps
                                    </button>
                                </a>
                            ) : (
                                []
                            )}
                        </div>
                    </div>
                </div>
            </div>
            <div className="row py-4">
                <div className="card">
                    <div className="card-header fw-bold">Process Graph</div>
                    <div className="card-body">
                        <ProcessGraphView
                            analysisId={analysis.id}
                            onElementSelect={handleSelectElement}
                        />
                    </div>
                </div>
            </div>
            <div className="row py-4">
                <div className="col">
                    <AnalysisReportTabs
                        analysis={analysis}
                        analysisSummary={analysisSummary}
                        selectedElement={selectedElement}
                        activeTab={activeTab}
                        onTabSwitch={setActiveTab}
                        onSelectProcess={handleSelectProcessById}
                    />
                </div>
            </div>
        </>
    );
}