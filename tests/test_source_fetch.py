import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'python'))
from runtime import collect, fetch

class FetchTests(unittest.TestCase):
    def test_retry_429_keeps_subscription_user_agent(self):
        error=HTTPError('https://example.com/sub',429,'limited',{'Retry-After':'3'},None)
        body=io.BytesIO(b'vless://test@8.8.8.8:443#test')
        body.headers={}
        with patch.object(fetch,'urlopen',side_effect=[error,body]) as request, \
             patch.object(fetch.time,'sleep') as sleep:
            result=fetch._fetch_candidate_body('https://example.com/sub',fetch._subscription_headers('https://example.com/sub'),8,[])
        self.assertTrue(result.startswith('vless://'))
        sleep.assert_called_once_with(3)
        self.assertEqual(request.call_count,2)
        self.assertEqual(request.call_args.args[0].get_header('User-agent'),'v2rayNG/1.10.8')

    def test_404_is_not_retried(self):
        error=HTTPError('https://example.com/missing',404,'missing',{},None)
        with patch.object(fetch,'urlopen',side_effect=error) as request, \
             patch.object(fetch.time,'sleep') as sleep:
            self.assertIsNone(fetch._fetch_candidate_body('https://example.com/missing',{},8,[]))
        self.assertEqual(request.call_count,1)
        sleep.assert_not_called()

    def test_empty_200_is_failed_source(self):
        outcomes=[]
        with patch.object(collect,'_fetch_text',return_value='# configs: 0\n'):
            nodes=collect._collect_from_source('https://example.com/empty',timeout=1,per_source_limit=0,
                log_sink=None,on_source_result=lambda url,ok:outcomes.append(ok))
        self.assertEqual(nodes,[])
        self.assertEqual(outcomes,[False])

    def test_retry_after_is_bounded_and_accepts_dates(self):
        self.assertEqual(fetch._rate_limit_delay('9999',0),60)
        self.assertEqual(fetch._rate_limit_delay('',1),4)
        self.assertEqual(fetch._rate_limit_delay('Wed, 21 Oct 2015 07:28:00 GMT',0),0)

if __name__=='__main__':
    unittest.main()
