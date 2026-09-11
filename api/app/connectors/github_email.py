import hashlib
import time
from urllib.parse import quote

import httpx

from app.models import GraphEdge, GraphNode, SourceRun
from .base import ConnectorResult


def _hid(value: object) -> str:
    return hashlib.sha256(str(value or '').encode()).hexdigest()[:16]


class GitHubEmailConnector:
    name = 'GitHub Public Email'

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        if kind != 'email':
            return ConnectorResult(run=SourceRun(name=self.name, status='skipped', message='Email only'))

        headers = {
            'Accept': 'application/vnd.github+json',
            'User-Agent': 'ExposureGraph/0.5',
            'X-GitHub-Api-Version': '2022-11-28',
        }
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                resp = await client.get(
                    'https://api.github.com/search/commits',
                    params={'q': f'author-email:{query.strip()}', 'per_page': 20},
                    headers=headers,
                )
                if resp.status_code == 403:
                    return ConnectorResult(run=SourceRun(name=self.name, status='error', message='GitHub public API rate limit reached'))
                resp.raise_for_status()
                items = (resp.json() or {}).get('items') or []

                nodes: list[GraphNode] = []
                edges: list[GraphEdge] = []
                seen_users: set[str] = set()
                for item in items[:20]:
                    user = item.get('author') or item.get('committer') or {}
                    login = str(user.get('login') or '').strip()
                    if not login:
                        continue
                    login_key = login.lower()
                    profile_id = f'github:profile:{_hid(login_key)}'
                    username_id = f'github:username:{_hid(login_key)}'
                    repo = item.get('repository') or {}
                    commit = item.get('commit') or {}
                    author = commit.get('author') or {}
                    props = {
                        'platform': 'GitHub',
                        'username': login,
                        'profile_url': f'https://github.com/{login}',
                        'github_user_id': user.get('id'),
                        'avatar_url': user.get('avatar_url'),
                        'commit_url': item.get('html_url'),
                        'repository': repo.get('full_name'),
                        'commit_date': author.get('date'),
                        'commit_message': commit.get('message'),
                        'match_reason': 'Exact public commit author email',
                    }
                    if login_key not in seen_users:
                        try:
                            profile_resp = await client.get(f'https://api.github.com/users/{quote(login)}', headers=headers)
                            if profile_resp.status_code == 200:
                                p = profile_resp.json()
                                props.update({
                                    'display_name': p.get('name'),
                                    'created_at': p.get('created_at'),
                                    'updated_at': p.get('updated_at'),
                                    'location': p.get('location'),
                                    'blog': p.get('blog'),
                                    'company': p.get('company'),
                                    'bio': p.get('bio'),
                                    'public_repos': p.get('public_repos'),
                                    'public_gists': p.get('public_gists'),
                                    'followers': p.get('followers'),
                                    'following': p.get('following'),
                                })
                        except Exception:
                            pass
                        nodes.append(GraphNode(id=username_id, type='username', label=login, properties={'username': login, 'source_profile': f'https://github.com/{login}'}, source=self.name, confidence=0.98, risk=5))
                        nodes.append(GraphNode(id=profile_id, type='socialaccount', label='GitHub', properties={k:v for k,v in props.items() if v not in (None, '')}, source=self.name, confidence=0.98, risk=5))
                        edges.append(GraphEdge(id=f'{root_id}->{username_id}', source=root_id, target=username_id, label='USES_USERNAME', source_name=self.name, confidence=0.98))
                        edges.append(GraphEdge(id=f'{username_id}->{profile_id}', source=username_id, target=profile_id, label='HAS_PUBLIC_PROFILE', source_name=self.name, confidence=0.98))
                        seen_users.add(login_key)
                    commit_id = str(item.get('sha') or _hid(item.get('html_url')))
                    commit_node_id = f'github:commit:{commit_id}'
                    nodes.append(GraphNode(id=commit_node_id, type='evidence', label=str(repo.get('full_name') or 'GitHub commit'), properties={'profile_url': item.get('html_url'), 'repository': repo.get('full_name'), 'commit_message': commit.get('message'), 'commit_date': author.get('date'), 'username': login}, source=self.name, confidence=0.98, risk=5))
                    edges.append(GraphEdge(id=f'{profile_id}->{commit_node_id}', source=profile_id, target=commit_node_id, label='AUTHORED_PUBLIC_COMMIT', source_name=self.name, confidence=0.98))

            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(nodes=nodes, edges=edges, run=SourceRun(name=self.name, status='ok', message=f'{len(items)} matching public commit(s), {len(seen_users)} GitHub account(s)', duration_ms=elapsed))
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(name=self.name, status='error', message=str(exc), duration_ms=elapsed))