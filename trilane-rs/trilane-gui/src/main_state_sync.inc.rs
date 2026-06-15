async fn persist_runbook_snapshot(app: &AppHandle, snapshot: &RunbookState) {
    let state = app.state::<AppState>();
    if let Err(error) = state.state_store.save_runbook(snapshot).await {
        warn!("Failed to persist TriLane runbook snapshot: {error:#}");
    }
}

async fn save_and_emit_runbook(app: &AppHandle, snapshot: RunbookState) -> RunbookState {
    persist_runbook_snapshot(app, &snapshot).await;
    emit_fe(
        app,
        FrontendEvent::RunbookUpdated {
            state: Box::new(snapshot.clone()),
        },
    );
    snapshot
}

async fn mutate_runbook<F>(app: &AppHandle, mutation: F) -> RunbookState
where
    F: FnOnce(&mut RunbookState),
{
    let snapshot = {
        let state = app.state::<AppState>();
        let mut runbook = state.runbook.lock().await;
        mutation(&mut runbook);
        runbook.clone()
    };
    save_and_emit_runbook(app, snapshot).await
}

async fn current_runbook_snapshot(state: &AppState) -> RunbookState {
    match state.state_store.load_runbook().await {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => state.runbook.lock().await.clone(),
        Err(error) => {
            warn!("Failed to load TriLane runbook snapshot: {error:#}");
            state.runbook.lock().await.clone()
        }
    }
}
