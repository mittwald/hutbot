import pytest
from unittest.mock import AsyncMock, patch
from bot import replace_ids, Channel, User, Usergroup

@pytest.mark.asyncio
async def test_replace_ids_user_id():
    app = AsyncMock()
    text = "Hello <@U12345>!"
    
    app.client.users_info.return_value = {"user": {"id": "U12345", "real_name": "John Doe"}}
    
    with patch('bot.get_user_by_id', return_value=User(id="U12345", name="johndoe", real_name="John Doe", team="team1")):
        result = await replace_ids(app, None, text)
    
    assert result == "Hello John Doe!"

@pytest.mark.asyncio
async def test_replace_ids_channel_id():
    app = AsyncMock()
    text = "Check out <#C67890> channel."
    
    app.client.conversations_info.return_value = {"channel": {"id": "C67890", "name": "random"}}
    
    with patch('bot.get_channel_by_id', return_value=Channel(id="C67890", name="random", config={})):
        result = await replace_ids(app, None, text)
    
    assert result == "Check out #random channel."

@pytest.mark.asyncio
async def test_replace_ids_fallback():
    app = AsyncMock()
    text = "Hello <@U99999|unknown>!"
    
    with patch('bot.get_user_by_id', return_value=User(id=None, name="unknown", real_name="", team="")):
        result = await replace_ids(app, None, text)
    
    assert result == "Hello unknown!"

@pytest.mark.asyncio
async def test_replace_ids_no_user():
    app = AsyncMock()
    text = "Hello <@U99999|>!"
    
    with patch('bot.get_user_by_id', return_value=User(id=None, name="unknown", real_name="", team="")):
        result = await replace_ids(app, None, text)
    
    assert result == "Hello @U99999!"
    
@pytest.mark.asyncio
async def test_replace_ids_usergroup():
    app = AsyncMock()
    text = "Hello <!subteam^S07RS6NT467>!"
    
    with patch('bot.get_usergroup_by_id', return_value=Usergroup(id="S07RS6NT467", handle="supergroup", name="The Super Group")):
        result = await replace_ids(app, None, text)
    
    assert result == "Hello @supergroup!"

@pytest.mark.asyncio
async def test_replace_ids_no_match():
    app = AsyncMock()
    text = "Hello world!"
    
    result = await replace_ids(app, None, text)
    
    assert result == "Hello world!"