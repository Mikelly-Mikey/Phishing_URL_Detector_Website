import { useState, useEffect } from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import axios from "axios";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Shield, AlertTriangle, CheckCircle, Download, History, Loader2, ShieldAlert, Lock } from "lucide-react";
import { toast } from "sonner";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const Home = () => {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [activeTab, setActiveTab] = useState("scanner");

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const response = await axios.get(`${API}/scan-history`);
      setHistory(response.data);
    } catch (error) {
      console.error("Error fetching history:", error);
    }
  };

  const handleCheckUrl = async () => {
    if (!url.trim()) {
      toast.error("Please enter a URL");
      return;
    }

    // Basic URL validation
    try {
      new URL(url);
    } catch {
      toast.error("Please enter a valid URL (include http:// or https://)");
      return;
    }

    setLoading(true);
    setResult(null);

    try {
      const response = await axios.post(`${API}/check-url`, { url });
      setResult(response.data);
      toast.success("URL analysis complete!");
      fetchHistory();
    } catch (error) {
      console.error("Error checking URL:", error);
      toast.error("Failed to analyze URL. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleDownloadPDF = async (scanId) => {
    try {
      const response = await axios.get(`${API}/scan/${scanId}/pdf`, {
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `phishing_report_${scanId}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      toast.success("PDF report downloaded!");
    } catch (error) {
      console.error("Error downloading PDF:", error);
      toast.error("Failed to download PDF report");
    }
  };

  const getRiskColor = (category) => {
    switch (category) {
      case "benign":
        return "bg-emerald-500";
      case "suspicious":
        return "bg-amber-500";
      case "malicious":
        return "bg-rose-500";
      default:
        return "bg-gray-500";
    }
  };

  const getRiskIcon = (category) => {
    switch (category) {
      case "benign":
        return <CheckCircle className="w-16 h-16 text-emerald-500" />;
      case "suspicious":
        return <AlertTriangle className="w-16 h-16 text-amber-500" />;
      case "malicious":
        return <ShieldAlert className="w-16 h-16 text-rose-500" />;
      default:
        return <Shield className="w-16 h-16 text-gray-500" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "high":
        return "bg-rose-100 text-rose-800 border-rose-300";
      case "medium":
        return "bg-amber-100 text-amber-800 border-amber-300";
      case "low":
        return "bg-blue-100 text-blue-800 border-blue-300";
      default:
        return "bg-gray-100 text-gray-800 border-gray-300";
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50">
      {/* Header */}
      <header className="border-b bg-white/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-indigo-600" />
              <h1 className="text-2xl font-bold text-slate-900">SafeCheck</h1>
            </div>
            <Badge variant="outline" className="gap-2">
              <Lock className="w-3 h-3" />
              Privacy Protected
            </Badge>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full max-w-md mx-auto grid-cols-2 mb-8">
            <TabsTrigger value="scanner" data-testid="scanner-tab">URL Scanner</TabsTrigger>
            <TabsTrigger value="history" data-testid="history-tab">Scan History</TabsTrigger>
          </TabsList>

          {/* Scanner Tab */}
          <TabsContent value="scanner" className="space-y-8">
            {/* Hero Section */}
            <div className="text-center space-y-4 py-8">
              <h2 className="text-4xl md:text-5xl font-bold text-slate-900">
                Advanced Phishing Detection
              </h2>
              <p className="text-lg text-slate-600 max-w-2xl mx-auto">
                Multi-layered AI-powered analysis to protect you from malicious URLs and phishing attacks
              </p>
            </div>

            {/* URL Input */}
            <Card className="max-w-3xl mx-auto shadow-lg">
              <CardHeader>
                <CardTitle className="text-2xl">Check URL Safety</CardTitle>
                <CardDescription>
                  Enter any URL to analyze for phishing, malware, and other threats
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex gap-3">
                  <Input
                    data-testid="url-input"
                    placeholder="https://example.com"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleCheckUrl()}
                    className="flex-1 h-12 text-base"
                    disabled={loading}
                  />
                  <Button
                    data-testid="check-url-button"
                    onClick={handleCheckUrl}
                    disabled={loading}
                    className="h-12 px-8 bg-indigo-600 hover:bg-indigo-700"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Shield className="w-4 h-4 mr-2" />
                        Check URL
                      </>
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Results */}
            {result && (
              <div className="space-y-6 max-w-5xl mx-auto">
                {/* Risk Overview */}
                <Card className="shadow-lg" data-testid="result-card">
                  <CardHeader className="text-center pb-4">
                    <div className="flex justify-center mb-4">
                      {getRiskIcon(result.risk_category)}
                    </div>
                    <CardTitle className="text-3xl">
                      {result.risk_category.charAt(0).toUpperCase() + result.risk_category.slice(1)}
                    </CardTitle>
                    <CardDescription className="text-base">{result.masked_url}</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-6">
                    {/* Risk Score */}
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm font-medium">Risk Score</span>
                        <span className="text-sm font-bold" data-testid="risk-score">{result.confidence_score.toFixed(1)}%</span>
                      </div>
                      <Progress value={result.confidence_score} className="h-3" />
                    </div>

                    {/* Summary */}
                    <Alert className={result.risk_category === 'malicious' ? 'border-rose-500 bg-rose-50' : result.risk_category === 'suspicious' ? 'border-amber-500 bg-amber-50' : 'border-emerald-500 bg-emerald-50'}>
                      <AlertTitle className="text-lg font-semibold" data-testid="risk-category">{result.risk_category.toUpperCase()}</AlertTitle>
                      <AlertDescription className="text-base" data-testid="result-summary">
                        {result.summary}
                      </AlertDescription>
                    </Alert>

                    {/* Threat Types */}
                    {result.detected_threat_types.length > 0 && (
                      <div>
                        <h4 className="font-semibold mb-3">Detected Threats</h4>
                        <div className="flex flex-wrap gap-2">
                          {result.detected_threat_types.map((threat, idx) => (
                            <Badge key={idx} variant="destructive" className="text-sm">
                              {threat}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Download PDF */}
                    <Button
                      data-testid="download-pdf-button"
                      onClick={() => handleDownloadPDF(result.id)}
                      variant="outline"
                      className="w-full"
                    >
                      <Download className="w-4 h-4 mr-2" />
                      Download PDF Report
                    </Button>
                  </CardContent>
                </Card>

                {/* Detailed Analysis */}
                <Card className="shadow-lg">
                  <CardHeader>
                    <CardTitle>Detailed Analysis</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Accordion type="single" collapsible className="w-full">
                      {/* Layer 1: Pattern Analysis */}
                      <AccordionItem value="patterns">
                        <AccordionTrigger data-testid="patterns-accordion">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold">Layer 1: Pattern Analysis</span>
                            <Badge variant="outline">{result.suspicious_patterns.length} patterns</Badge>
                          </div>
                        </AccordionTrigger>
                        <AccordionContent>
                          {result.suspicious_patterns.length > 0 ? (
                            <div className="space-y-3">
                              {result.suspicious_patterns.map((pattern, idx) => (
                                <div key={idx} className="border rounded-lg p-4 space-y-2">
                                  <div className="flex items-center justify-between">
                                    <span className="font-medium">{pattern.category}</span>
                                    <Badge className={getSeverityColor(pattern.severity)}>
                                      {pattern.severity}
                                    </Badge>
                                  </div>
                                  <p className="text-sm text-slate-600">{pattern.description}</p>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-slate-600">No suspicious patterns detected</p>
                          )}
                        </AccordionContent>
                      </AccordionItem>

                      {/* Layer 2: Threat Intelligence */}
                      <AccordionItem value="threat">
                        <AccordionTrigger data-testid="threat-accordion">
                          <span className="font-semibold">Layer 2: Threat Intelligence</span>
                        </AccordionTrigger>
                        <AccordionContent>
                          <p className="text-slate-700">{result.threat_intelligence_result}</p>
                        </AccordionContent>
                      </AccordionItem>

                      {/* Layer 3: AI Analysis */}
                      <AccordionItem value="ai">
                        <AccordionTrigger data-testid="ai-accordion">
                          <span className="font-semibold">Layer 3: AI/ML Detection</span>
                        </AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-4">
                            <div>
                              <div className="flex justify-between mb-1">
                                <span className="text-sm">URL Model Score</span>
                                <span className="text-sm font-bold">{result.ai_scores.url_model_score.toFixed(1)}%</span>
                              </div>
                              <Progress value={result.ai_scores.url_model_score} className="h-2" />
                            </div>
                            <div>
                              <div className="flex justify-between mb-1">
                                <span className="text-sm">Content Model Score</span>
                                <span className="text-sm font-bold">{result.ai_scores.content_model_score.toFixed(1)}%</span>
                              </div>
                              <Progress value={result.ai_scores.content_model_score} className="h-2" />
                            </div>
                            <div>
                              <div className="flex justify-between mb-1">
                                <span className="text-sm">Ensemble Score</span>
                                <span className="text-sm font-bold">{result.ai_scores.ensemble_score.toFixed(1)}%</span>
                              </div>
                              <Progress value={result.ai_scores.ensemble_score} className="h-2" />
                            </div>
                            <div className="pt-2 border-t">
                              <span className="text-sm text-slate-600">AI Confidence: {result.ai_scores.confidence.toFixed(1)}%</span>
                            </div>
                          </div>
                        </AccordionContent>
                      </AccordionItem>

                      {/* Layer 4: Dynamic Analysis */}
                      <AccordionItem value="dynamic">
                        <AccordionTrigger data-testid="dynamic-accordion">
                          <span className="font-semibold">Layer 4: Dynamic Analysis</span>
                        </AccordionTrigger>
                        <AccordionContent>
                          <div className="space-y-4">
                            {result.dynamic_analysis.html_signals.length > 0 && (
                              <div>
                                <h5 className="font-medium mb-2">HTML Signals</h5>
                                <ul className="list-disc list-inside space-y-1">
                                  {result.dynamic_analysis.html_signals.map((signal, idx) => (
                                    <li key={idx} className="text-sm text-slate-600">{signal}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                            {result.dynamic_analysis.javascript_behaviors.length > 0 && (
                              <div>
                                <h5 className="font-medium mb-2">JavaScript Behaviors</h5>
                                <ul className="list-disc list-inside space-y-1">
                                  {result.dynamic_analysis.javascript_behaviors.map((behavior, idx) => (
                                    <li key={idx} className="text-sm text-slate-600">{behavior}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                            <div className="pt-2 border-t">
                              <span className="text-sm font-medium">Credential Harvesting: </span>
                              <span className={`text-sm ${result.dynamic_analysis.credential_harvesting_detected ? 'text-rose-600 font-bold' : 'text-emerald-600'}`}>
                                {result.dynamic_analysis.credential_harvesting_detected ? 'DETECTED' : 'Not Detected'}
                              </span>
                            </div>
                          </div>
                        </AccordionContent>
                      </AccordionItem>

                      {/* Privacy Status */}
                      <AccordionItem value="privacy">
                        <AccordionTrigger data-testid="privacy-accordion">
                          <span className="font-semibold">Privacy & Compliance</span>
                        </AccordionTrigger>
                        <AccordionContent>
                          <div className="flex items-start gap-3 p-4 bg-blue-50 border border-blue-200 rounded-lg">
                            <Lock className="w-5 h-5 text-blue-600 mt-0.5" />
                            <p className="text-sm text-slate-700">{result.privacy_status}</p>
                          </div>
                        </AccordionContent>
                      </AccordionItem>
                    </Accordion>
                  </CardContent>
                </Card>
              </div>
            )}
          </TabsContent>

          {/* History Tab */}
          <TabsContent value="history" className="space-y-6">
            <Card className="max-w-5xl mx-auto shadow-lg">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <History className="w-5 h-5" />
                  Recent Scans
                </CardTitle>
                <CardDescription>View your recent URL security scans</CardDescription>
              </CardHeader>
              <CardContent>
                {history.length > 0 ? (
                  <div className="space-y-3">
                    {history.map((scan) => (
                      <div
                        key={scan.id}
                        className="flex items-center justify-between p-4 border rounded-lg hover:bg-slate-50 transition-colors"
                        data-testid="history-item"
                      >
                        <div className="flex-1 min-w-0">
                          <p className="font-medium text-slate-900 truncate">{scan.masked_url}</p>
                          <p className="text-sm text-slate-500">
                            {new Date(scan.timestamp).toLocaleString()}
                          </p>
                        </div>
                        <div className="flex items-center gap-3">
                          <Badge className={getRiskColor(scan.risk_category)}>
                            {scan.risk_category}
                          </Badge>
                          <span className="text-sm font-bold text-slate-700">
                            {scan.confidence_score.toFixed(0)}%
                          </span>
                          <Button
                            data-testid={`download-pdf-${scan.id}`}
                            size="sm"
                            variant="outline"
                            onClick={() => handleDownloadPDF(scan.id)}
                          >
                            <Download className="w-4 h-4" />
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-12">
                    <Shield className="w-16 h-16 text-slate-300 mx-auto mb-4" />
                    <p className="text-slate-500">No scans yet. Start by checking a URL!</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t bg-white/80 backdrop-blur-sm mt-16">
        <div className="container mx-auto px-4 py-6 text-center text-sm text-slate-600">
          <p>SafeCheck - Advanced Phishing Detection System</p>
          <p className="mt-1">Powered by AI/ML & Real-time Threat Intelligence</p>
        </div>
      </footer>
    </div>
  );
};

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Home />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;