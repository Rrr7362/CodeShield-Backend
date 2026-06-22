// testGithub.js — run with: node testGithub.js
import { getRepoMetadata, getTreeSha, getRepoTree } from './src/services/githubService.js';

async function test() {
  try {
    const owner = 'expressjs';
    const repo = 'express';

    console.log('--- Testing getRepoMetadata ---');
    const metadata = await getRepoMetadata(owner, repo);
    console.log(metadata);

    console.log('\n--- Testing getTreeSha ---');
    const treeSha = await getTreeSha(owner, repo, metadata.defaultBranch);
    console.log('Tree SHA:', treeSha);

    console.log('\n--- Testing getRepoTree ---');
    const tree = await getRepoTree(owner, repo, treeSha);
    console.log(`Total entries: ${tree.length}`);
    console.log(`Blob entries: ${tree.filter(n => n.type === 'blob').length}`);
    console.log(`Tree entries: ${tree.filter(n => n.type === 'tree').length}`);
    console.log('First 3 entries:', tree.slice(0, 3));

  } catch (err) {
    console.error('Test failed:', err.message, err.code);
  }
}

test();