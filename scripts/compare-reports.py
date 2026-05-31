      - name: Fetch Current Active Scanner Artifacts Pool
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const path = require('path');
            
            console.log("🔍 Locating the most recent completed pipeline runs...");
            mkdirSyncRecursive('all-results');

            // 1. Find the latest completed Automated Scan run ID
            const aiRuns = await github.rest.actions.listWorkflowRuns({
              owner: context.repo.owner,
              repo: context.repo.repo,
              workflow_id: 'codeql-scan.yml', // Targets your main workflow filename
              status: 'completed',
              per_page: 1
            });

            // 2. Find the latest completed Human Scan run ID
            const humanRuns = await github.rest.actions.listWorkflowRuns({
              owner: context.repo.owner,
              repo: context.repo.repo,
              workflow_id: 'human-codeql-scan.yml', // Targets your human workflow filename
              status: 'completed',
              per_page: 1
            });

            const targetRunIds = [];
            if (aiRuns.data.workflow_runs.length > 0) {
              targetRunIds.push(aiRuns.data.workflow_runs[0].id);
              console.log(`🤖 Found active AI Scan Run ID: ${aiRuns.data.workflow_runs[0].id}`);
            }
            if (humanRuns.data.workflow_runs.length > 0) {
              targetRunIds.push(humanRuns.data.workflow_runs[0].id);
              console.log(`👨‍💻 Found active Human Scan Run ID: ${humanRuns.data.workflow_runs[0].id}`);
            }

            // 3. Download artifacts specifically linked to these active runs only
            for (const runId of targetRunIds) {
              const response = await github.rest.actions.listWorkflowRunArtifacts({
                owner: context.repo.owner,
                repo: context.repo.repo,
                run_id: runId
              });

              const artifacts = response.data.artifacts.filter(art => art.name.startsWith('sarif-'));
              
              for (const artifact of artifacts) {
                try {
                  console.log(`📥 Ingesting active run file: ${artifact.name}`);
                  const zip = await github.rest.actions.downloadArtifact({
                    owner: context.repo.owner,
                    repo: context.repo.repo,
                    artifact_id: artifact.id,
                    archive_format: 'zip',
                  });

                  const targetDir = path.join('all-results', artifact.name);
                  mkdirSyncRecursive(targetDir);
                  fs.writeFileSync(path.join(targetDir, 'artifact.zip'), Buffer.from(zip.data));
                  execSync(`unzip -o "${path.join(targetDir, 'artifact.zip')}" -d "${targetDir}" && rm "${path.join(targetDir, 'artifact.zip')}"`);
                } catch (err) {
                  console.log(`⚠️ Skip packet download error for ${artifact.name}: ${err.message}`);
                }
              }
            }

            function mkdirSyncRecursive(dir) {
              if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            }
            function execSync(cmd) {
              require('child_process').execSync(cmd, { stdio: 'ignore' });
            }
