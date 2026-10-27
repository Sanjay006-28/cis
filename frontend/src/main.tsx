import React, { lazy, Suspense } from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import "./styles.css";

const AboutPage = lazy(() => import("./pages/AboutPage").then((module) => ({ default: module.AboutPage })));
const AnalyzePage = lazy(() => import("./pages/AnalyzePage").then((module) => ({ default: module.AnalyzePage })));
const DynamicPage = lazy(() => import("./pages/DynamicPage").then((module) => ({ default: module.DynamicPage })));
const EnvironmentPage = lazy(() => import("./pages/EnvironmentPage").then((module) => ({ default: module.EnvironmentPage })));
const NotFoundPage = lazy(() => import("./pages/NotFoundPage").then((module) => ({ default: module.NotFoundPage })));
const OverviewPage = lazy(() => import("./pages/OverviewPage").then((module) => ({ default: module.OverviewPage })));
const ResearchPage = lazy(() => import("./pages/ResearchPage").then((module) => ({ default: module.ResearchPage })));

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <Suspense fallback={<main className="page-content"><p className="section-description">Loading workspace…</p></main>}>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<OverviewPage />} />
            <Route path="analyze" element={<AnalyzePage />} />
            <Route path="dynamic" element={<DynamicPage />} />
            <Route path="environment" element={<EnvironmentPage />} />
            <Route path="research" element={<ResearchPage />} />
            <Route path="about" element={<AboutPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </Suspense>
    </BrowserRouter>
  </React.StrictMode>,
);
